//go:build linux

package software

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	dockerPostureTimeout        = 45 * time.Second
	dockerPostureInspectCap     = 48
	dockerPostureOverlayNetCap  = 24
	dockerPostureInfoMaxBytes   = 768 * 1024
	dockerSockMountSubstr       = "docker.sock"
	defaultDockerDaemonJSONPath = "/etc/docker/daemon.json"
)

var dockerDangerousCaps = map[string]struct{}{
	"SYS_ADMIN": {}, "SYS_PTRACE": {}, "NET_ADMIN": {}, "NET_RAW": {},
	"DAC_OVERRIDE": {}, "SYS_RAWIO": {}, "SYS_MODULE": {},
}

type dockerDaemonPostureJSON struct {
	LiveRestore       *bool           `json:"live-restore"`
	Icc               *bool           `json:"icc"`
	UsernsRemap       string          `json:"userns-remap"`
	NoNewPrivileges   *bool           `json:"no-new-privileges"`
	LogDriver         string          `json:"log-driver"`
	SeccompProfile    string          `json:"seccomp-profile"`
	DefaultUlimits    json.RawMessage `json:"default-ulimits"`
	Hosts             []string        `json:"hosts"`
}

type dockerInfoPosture struct {
	StorageDriver     string   `json:"StorageDriver"`
	SecurityOptions   []string `json:"SecurityOptions"`
	Rootless          bool     `json:"Rootless"`
	KernelVersion     string   `json:"KernelVersion"`
	DockerRootDir     string   `json:"DockerRootDir"`
	ContainersRunning int      `json:"ContainersRunning"`
	Swarm             struct {
		LocalNodeState string `json:"LocalNodeState"`
	} `json:"Swarm"`
}

type dockerInspectPosture struct {
	ID              string `json:"Id"`
	Name            string `json:"Name"`
	AppArmorProfile string `json:"AppArmorProfile"`
	Config          struct {
		User        string          `json:"User"`
		Image       string          `json:"Image"`
		Healthcheck json.RawMessage `json:"Healthcheck"`
	} `json:"Config"`
	HostConfig struct {
		Privileged     bool     `json:"Privileged"`
		PidMode        string   `json:"PidMode"`
		NetworkMode    string   `json:"NetworkMode"`
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
		CapAdd         []string `json:"CapAdd"`
		CapDrop        []string `json:"CapDrop"`
		SecurityOpt    []string `json:"SecurityOpt"`
		Binds          []string `json:"Binds"`
		Memory         int64    `json:"Memory"`
		NanoCpus       int64    `json:"NanoCpus"`
		PidsLimit      *int64   `json:"PidsLimit"`
		SeccompProfile string   `json:"SeccompProfile"`
	} `json:"HostConfig"`
	Mounts []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIp   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

type dockerNetworkInspectPosture struct {
	Name    string            `json:"Name"`
	Driver  string            `json:"Driver"`
	Options map[string]string `json:"Options"`
}

// CollectDockerPosture collects Docker host security posture (read-only docker CLI and filesystem checks).
func CollectDockerPosture(ctx context.Context) *payload.DockerPosture {
	out := &payload.DockerPosture{
		ContainerRisks:               []payload.DockerContainerRisk{},
		DockerSockMountedInContainers: []string{},
		ImagesRunningAsLatest:        []string{},
		ImagesWithoutHealthcheck:     []string{},
		PublishedPorts:               []payload.DockerPublishedPort{},
		CustomNetworksEncrypted:      []payload.DockerOverlayNetworkEncryption{},
		DockerGroupMembers:           []string{},
		CollectorWarnings:            []string{},
	}
	dockerPath, errDocker := exec.LookPath("docker")
	hasCLI := errDocker == nil && dockerPath != ""
	sockPath := resolveDockerSocketPath()
	daemonJSONPath := defaultDockerDaemonJSONPath
	dockerd := scanDockerdProcess()
	if dockerd.configFile != "" {
		daemonJSONPath = dockerd.configFile
	}
	hasDaemonJSON := shared.FileExistsRegular(daemonJSONPath)
	dockerdUp := dockerd.pid > 0
	if !hasCLI && sockPath == "" && !hasDaemonJSON && !dockerdUp {
		return nil
	}
	out.Detected = true
	if sockPath != "" {
		out.DockerSockPath = shared.StringPtr(sockPath)
		fillDockerSockPosture(out, sockPath)
	}
	subCtx, cancel := context.WithTimeout(ctx, dockerPostureTimeout)
	defer cancel()
	if hasCLI {
		out.DockerCliPath = shared.StringPtr(dockerPath)
		verLine, apiLine := dockerServerVersionLines(subCtx, dockerPath)
		if verLine != "" {
			out.Version = shared.StringPtr(shared.TruncateRunes(verLine, 256))
		}
		if apiLine != "" {
			out.APIVersion = shared.StringPtr(shared.TruncateRunes(apiLine, 64))
		}
		if raw, err := runDockerOutput(subCtx, dockerPath, "info", "--format", "{{json .}}"); err != nil {
			out.CollectorWarnings = append(out.CollectorWarnings, shared.TruncateRunes("docker info: "+err.Error(), 256))
		} else {
			applyDockerInfoPosture(out, raw)
		}
	} else {
		out.CollectorWarnings = append(out.CollectorWarnings, "docker CLI not on PATH; daemon details limited to filesystem/process hints")
	}
	var daemonData *dockerDaemonPostureJSON
	if daemonData = readDaemonJSONPosture(daemonJSONPath); daemonData != nil {
		applyDaemonJSONPosture(out, daemonData)
		appendDaemonJSONFindingWarnings(out)
	} else if hasDaemonJSON {
		out.CollectorWarnings = append(out.CollectorWarnings, "daemon.json present but not readable or invalid JSON")
	}
	hostsFromJSON := []string(nil)
	if daemonData != nil {
		hostsFromJSON = daemonData.Hosts
	}
	tcpMerged := mergeTCPHints(dockerd.tcpHosts, tcpListenersFromStrings(hostsFromJSON))
	if len(tcpMerged) > 0 {
		t := true
		out.TCPAPIExposed = &t
		out.TCPAPIAddress = shared.StringPtr(shared.TruncateRunes(strings.Join(tcpMerged, ", "), 512))
		tlsOn := dockerd.tlsVerify || daemonJSONTLSVerify(daemonJSONPath)
		out.TCPAPITLSEnabled = shared.BoolPtr(tlsOn)
		if !tlsOn {
			out.CollectorWarnings = append(out.CollectorWarnings, "Docker TCP listener without TLS verification is effectively unauthenticated remote root")
		}
	}
	finalizeDockerRootless(out, sockPath, dockerd)
	if out.IccEnabled != nil && *out.IccEnabled {
		out.CollectorWarnings = append(out.CollectorWarnings, "ICC (inter-container communication) is not disabled; default bridge allows lateral movement between containers")
	}
	dataRoot := "/var/lib/docker"
	if out.DockerRootDir != nil && strings.TrimSpace(*out.DockerRootDir) != "" {
		dataRoot = strings.TrimSpace(*out.DockerRootDir)
	}
	out.DockerDataPermissions = filePermSummaryString(dataRoot)
	out.DockerGroupMembers = dockerGroupMembers(subCtx)
	if hasCLI {
		if out.ContainerCount != nil && *out.ContainerCount > 0 {
			ids := dockerRunningIDs(subCtx, dockerPath, dockerPostureInspectCap)
			if len(ids) > 0 {
				inspectDockerContainers(subCtx, dockerPath, ids, dataRoot, out)
			}
		}
		overlayNetInspect(subCtx, dockerPath, out)
	}
	return out
}

func finalizeDockerRootless(out *payload.DockerPosture, sockPath string, d dockerdScan) {
	rootless := out.RootlessMode != nil && *out.RootlessMode
	if d.rootlessArg {
		rootless = true
	}
	if d.pid > 0 && d.uid > 0 {
		rootless = true
	}
	if strings.Contains(sockPath, "/run/user/") {
		rootless = true
	}
	out.RootlessMode = shared.BoolPtr(rootless)
	if !rootless {
		out.CollectorWarnings = append(out.CollectorWarnings, "Docker engine is not rootless; a container escape can reach host root")
	}
}

func appendDaemonJSONFindingWarnings(out *payload.DockerPosture) {
	if out == nil {
		return
	}
	if out.LogDriver != nil && strings.EqualFold(strings.TrimSpace(*out.LogDriver), "none") {
		out.CollectorWarnings = append(out.CollectorWarnings, "log_driver is none; container logs are unavailable for forensics")
	}
	if out.SeccompProfile != nil && strings.EqualFold(strings.TrimSpace(*out.SeccompProfile), "unconfined") {
		out.CollectorWarnings = append(out.CollectorWarnings, "daemon seccomp-profile is unconfined")
	}
}

// applyDockerInfoPosture fills fields from docker info JSON; sets rootless hint on out via SecurityOptions.
func applyDockerInfoPosture(out *payload.DockerPosture, raw []byte) {
	if len(raw) > dockerPostureInfoMaxBytes {
		raw = raw[:dockerPostureInfoMaxBytes]
	}
	var info dockerInfoPosture
	if err := json.Unmarshal(raw, &info); err != nil {
		out.CollectorWarnings = append(out.CollectorWarnings, "docker info JSON parse failed")
		return
	}
	if info.StorageDriver != "" {
		out.StorageDriver = shared.StringPtr(shared.TruncateRunes(info.StorageDriver, 128))
	}
	cr := info.ContainersRunning
	out.ContainerCount = &cr
	if info.KernelVersion != "" {
		out.KernelVersion = shared.StringPtr(shared.TruncateRunes(info.KernelVersion, 256))
	}
	if info.DockerRootDir != "" {
		out.DockerRootDir = shared.StringPtr(shared.TruncateRunes(info.DockerRootDir, 512))
	}
	rl := info.Rootless
	for _, opt := range info.SecurityOptions {
		if strings.Contains(strings.ToLower(opt), "rootless") {
			rl = true
			break
		}
	}
	out.RootlessMode = shared.BoolPtr(rl)
	swarm := strings.ToLower(strings.TrimSpace(info.Swarm.LocalNodeState))
	active := swarm == "active" || swarm == "locked"
	out.IsSwarmActive = shared.BoolPtr(active)
}

type dockerdScan struct {
	pid          int
	configFile   string
	tcpHosts     []string
	tlsVerify    bool
	rootlessArg  bool
	uid          int
}

func scanDockerdProcess() dockerdScan {
	var d dockerdScan
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return d
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 1 {
			continue
		}
		commPath := filepath.Join("/proc", e.Name(), "comm")
		commB, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(commB))
		if comm != "dockerd" {
			continue
		}
		cmdline := readProcCmdline(filepath.Join("/proc", e.Name(), "cmdline"))
		if len(cmdline) == 0 {
			continue
		}
		d.pid = pid
		d.uid = procStatusUID(filepath.Join("/proc", e.Name(), "status"))
		d.tcpHosts, d.tlsVerify, d.rootlessArg, d.configFile = parseDockerdArgs(cmdline)
		break
	}
	return d
}

func readProcCmdline(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return nil
	}
	var args []string
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == 0 {
			if i > start {
				args = append(args, string(b[start:i]))
			}
			start = i + 1
		}
	}
	return args
}

func procStatusUID(statusPath string) int {
	b, err := os.ReadFile(statusPath)
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				u, _ := strconv.Atoi(fields[1])
				return u
			}
		}
	}
	return -1
}

func parseDockerdArgs(args []string) (tcpHosts []string, tlsVerify, rootless bool, configFile string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--tlsverify":
			tlsVerify = true
		case a == "--rootless":
			rootless = true
		case a == "-H" || a == "--host":
			if i+1 < len(args) {
				i++
				if strings.HasPrefix(args[i], "tcp://") {
					tcpHosts = append(tcpHosts, strings.TrimPrefix(args[i], "tcp://"))
				}
			}
		case strings.HasPrefix(a, "-H=tcp://") || strings.HasPrefix(a, "--host=tcp://"):
			v := a[strings.Index(a, "tcp://"):]
			tcpHosts = append(tcpHosts, strings.TrimPrefix(v, "tcp://"))
		case a == "--config-file" && i+1 < len(args):
			i++
			configFile = args[i]
		case strings.HasPrefix(a, "--config-file="):
			configFile = strings.TrimPrefix(a, "--config-file=")
		}
	}
	return tcpHosts, tlsVerify, rootless, configFile
}

func mergeTCPHints(a, b []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, src := range [][]string{a, b} {
		for _, h := range src {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			out = append(out, h)
		}
	}
	return out
}

func tcpListenersFromStrings(hosts []string) []string {
	var out []string
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		h = strings.TrimPrefix(h, "tcp://")
		if strings.HasPrefix(h, "unix://") || h == "" {
			continue
		}
		out = append(out, h)
	}
	return out
}

func readDaemonJSONPosture(path string) *dockerDaemonPostureJSON {
	b, err := shared.ReadFileBounded(path, shared.DefaultConfigFileReadLimit)
	if err != nil {
		return nil
	}
	var d dockerDaemonPostureJSON
	if err := json.Unmarshal(b, &d); err != nil {
		return nil
	}
	return &d
}

func daemonJSONTLSVerify(path string) bool {
	d := readDaemonJSONPosture(path)
	if d == nil {
		return false
	}
	// Extended read for tlsverify in same file
	b, err := shared.ReadFileBounded(path, shared.DefaultConfigFileReadLimit)
	if err != nil {
		return false
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return false
	}
	if v, ok := raw["tlsverify"]; ok {
		var bval bool
		if json.Unmarshal(v, &bval) == nil && bval {
			return true
		}
	}
	return false
}

func applyDaemonJSONPosture(out *payload.DockerPosture, d *dockerDaemonPostureJSON) {
	if strings.TrimSpace(d.UsernsRemap) != "" {
		out.UsernsRemap = shared.StringPtr(shared.TruncateRunes(strings.TrimSpace(d.UsernsRemap), 128))
	}
	out.NoNewPrivileges = d.NoNewPrivileges
	if d.Icc != nil {
		out.IccEnabled = shared.BoolPtr(*d.Icc)
	} else {
		out.IccEnabled = shared.BoolPtr(true)
	}
	out.LiveRestore = d.LiveRestore
	if strings.TrimSpace(d.LogDriver) != "" {
		out.LogDriver = shared.StringPtr(shared.TruncateRunes(strings.TrimSpace(d.LogDriver), 64))
	}
	if strings.TrimSpace(d.SeccompProfile) != "" {
		out.SeccompProfile = shared.StringPtr(shared.TruncateRunes(strings.TrimSpace(d.SeccompProfile), 512))
	}
	if len(d.DefaultUlimits) > 0 && string(d.DefaultUlimits) != "null" {
		out.DefaultUlimits = shared.StringPtr(shared.TruncateRunes(string(d.DefaultUlimits), 2048))
	}
}

func dockerServerVersionLines(ctx context.Context, dockerPath string) (version, api string) {
	vb, err := runDockerOutput(ctx, dockerPath, "version", "--format", "{{.Server.Version}}")
	if err == nil {
		version = strings.TrimSpace(string(vb))
	}
	ab, err := runDockerOutput(ctx, dockerPath, "version", "--format", "{{.Server.APIVersion}}")
	if err == nil {
		api = strings.TrimSpace(string(ab))
	}
	return version, api
}

func runDockerOutput(ctx context.Context, dockerPath string, args ...string) ([]byte, error) {
	if err := shared.ScanContextError(ctx); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, dockerPath, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.Bytes(), err
}

func fillDockerSockPosture(out *payload.DockerPosture, sockPath string) {
	st, err := os.Stat(sockPath)
	if err != nil {
		slog.Debug("docker posture socket stat failed", "path", sockPath, "error", err)
		return
	}
	mode := st.Mode().Perm()
	out.DockerSockModeOctal = shared.StringPtr(fmt.Sprintf("%04o", mode))
	sys, ok := st.Sys().(*syscall.Stat_t)
	if ok {
		u := int(sys.Uid)
		g := int(sys.Gid)
		out.DockerSockOwnerUID = &u
		out.DockerSockGroupGID = &g
	}
	if mode&0o077 != 0 {
		out.CollectorWarnings = append(out.CollectorWarnings, "docker.sock is world-accessible (group/other bits set)")
	}
}

func filePermSummaryString(path string) *string {
	st, err := os.Stat(path)
	if err != nil {
		return nil
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return shared.StringPtr(fmt.Sprintf("mode=%04o", st.Mode().Perm()))
	}
	return shared.StringPtr(fmt.Sprintf("mode=%04o uid=%d gid=%d", st.Mode().Perm(), int(sys.Uid), int(sys.Gid)))
}

func dockerGroupMembers(ctx context.Context) []string {
	if err := shared.ScanContextError(ctx); err != nil {
		return nil
	}
	cmd := exec.CommandContext(ctx, "getent", "group", "docker")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	line := strings.TrimSpace(string(out))
	parts := strings.Split(line, ":")
	if len(parts) < 4 {
		return nil
	}
	members := strings.TrimSpace(parts[3])
	if members == "" {
		return []string{}
	}
	var names []string
	for _, m := range strings.Split(members, ",") {
		m = strings.TrimSpace(m)
		if m != "" {
			names = append(names, m)
		}
	}
	return names
}

func dockerRunningIDs(ctx context.Context, dockerPath string, capN int) []string {
	raw, err := runDockerOutput(ctx, dockerPath, "ps", "-q", "--no-trunc")
	if err != nil {
		return nil
	}
	var ids []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			ids = append(ids, line)
		}
		if len(ids) >= capN {
			break
		}
	}
	return ids
}

func inspectDockerContainers(ctx context.Context, dockerPath string, ids []string, dataRoot string, out *payload.DockerPosture) {
	args := append([]string{"inspect"}, ids...)
	raw, err := runDockerOutput(ctx, dockerPath, args...)
	if err != nil {
		out.CollectorWarnings = append(out.CollectorWarnings, "docker inspect failed for running containers")
		return
	}
	var arr []dockerInspectPosture
	if err := json.Unmarshal(raw, &arr); err != nil {
		out.CollectorWarnings = append(out.CollectorWarnings, "docker inspect JSON parse failed")
		return
	}
	latestSeen := make(map[string]struct{})
	noHealthSeen := make(map[string]struct{})
	for _, c := range arr {
		name := strings.TrimPrefix(c.Name, "/")
		idShort := c.ID
		if len(idShort) > 12 {
			idShort = idShort[:12]
		}
		if name == "" {
			name = idShort
		}
		img := strings.TrimSpace(c.Config.Image)
		if imageTagIsLatest(img) {
			if _, ok := latestSeen[img]; !ok {
				latestSeen[img] = struct{}{}
				out.ImagesRunningAsLatest = append(out.ImagesRunningAsLatest, shared.TruncateRunes(img, 256))
			}
		}
		if !hasHealthcheckDefined(c.Config.Healthcheck) {
			key := img
			if key == "" {
				key = c.ID
			}
			if _, ok := noHealthSeen[key]; !ok {
				noHealthSeen[key] = struct{}{}
				out.ImagesWithoutHealthcheck = append(out.ImagesWithoutHealthcheck, shared.TruncateRunes(key, 256))
			}
		}
		risk := buildContainerRisk(c, name, idShort, dataRoot)
		if risk != nil {
			out.ContainerRisks = append(out.ContainerRisks, *risk)
		}
		ports := extractPublishedPorts(name, idShort, c)
		out.PublishedPorts = append(out.PublishedPorts, ports...)
		if sockMount := dockerSockBindSummary(c); sockMount != "" {
			out.DockerSockMountedInContainers = append(out.DockerSockMountedInContainers, sockMount)
		}
	}
}

func imageTagIsLatest(imageRef string) bool {
	imageRef = strings.TrimSpace(imageRef)
	if imageRef == "" || strings.Contains(imageRef, "@") {
		return false
	}
	i := strings.LastIndex(imageRef, "/")
	tail := imageRef
	if i >= 0 {
		tail = imageRef[i+1:]
	}
	if idx := strings.LastIndex(tail, ":"); idx >= 0 {
		tag := strings.ToLower(strings.TrimSpace(tail[idx+1:]))
		return tag == "latest"
	}
	return true
}

func hasHealthcheckDefined(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return true
	}
	t, ok := m["Test"]
	if !ok {
		return false
	}
	var tests []string
	if err := json.Unmarshal(t, &tests); err != nil {
		return true
	}
	return len(tests) > 0 && (len(tests) != 1 || tests[0] != "NONE")
}

func buildContainerRisk(c dockerInspectPosture, name, idShort, dataRoot string) *payload.DockerContainerRisk {
	var risk payload.DockerContainerRisk
	risk.Name = shared.TruncateRunes(name, 256)
	risk.ID = shared.TruncateRunes(idShort, 64)
	has := false
	if c.HostConfig.Privileged {
		t := true
		risk.Privileged = &t
		has = true
	}
	if strings.EqualFold(strings.TrimSpace(c.HostConfig.PidMode), "host") {
		t := true
		risk.PidModeHost = &t
		has = true
	}
	nm := strings.TrimSpace(c.HostConfig.NetworkMode)
	if nm == "host" || strings.HasSuffix(nm, ":host") {
		t := true
		risk.NetworkModeHost = &t
		has = true
	}
	var dangerous []string
	for _, cap := range c.HostConfig.CapAdd {
		up := strings.ToUpper(strings.TrimSpace(cap))
		if _, ok := dockerDangerousCaps[up]; ok {
			dangerous = append(dangerous, up)
		}
	}
	if len(dangerous) > 0 {
		risk.CapabilitiesAdded = dangerous
		has = true
	}
	if capDropMissingALL(c.HostConfig.CapDrop) {
		t := true
		risk.CapabilitiesNotDropped = &t
		has = true
	}
	if containerRunsAsRoot(c.Config.User) {
		t := true
		risk.RunsAsRoot = &t
		has = true
	}
	if !c.HostConfig.ReadonlyRootfs {
		t := true
		risk.WritableRootfs = &t
		has = true
	}
	sens := sensitiveMounts(c, dataRoot)
	if len(sens) > 0 {
		risk.SensitiveMounts = sens
		has = true
	}
	if noSecurityProfile(c) {
		t := true
		risk.NoSecurityProfile = &t
		has = true
	}
	if noResourceLimits(c) {
		t := true
		risk.NoResourceLimits = &t
		has = true
	}
	if !has {
		return nil
	}
	return &risk
}

func capDropMissingALL(drop []string) bool {
	for _, d := range drop {
		if strings.ToUpper(strings.TrimSpace(d)) == "ALL" {
			return false
		}
	}
	return true
}

func containerRunsAsRoot(user string) bool {
	user = strings.TrimSpace(user)
	if user == "" || user == "0" || strings.HasPrefix(user, "0:") {
		return true
	}
	low := strings.ToLower(user)
	if low == "root" || strings.HasPrefix(low, "root:") {
		return true
	}
	return false
}

func noSecurityProfile(c dockerInspectPosture) bool {
	aa := strings.TrimSpace(c.AppArmorProfile)
	aaWeak := aa == "" || strings.EqualFold(aa, "unconfined")
	sec := strings.TrimSpace(c.HostConfig.SeccompProfile)
	for _, o := range c.HostConfig.SecurityOpt {
		ol := strings.ToLower(o)
		if strings.Contains(ol, "apparmor=unconfined") {
			aaWeak = true
		}
		if strings.Contains(ol, "seccomp=unconfined") {
			sec = "unconfined"
		}
	}
	secWeak := sec == "" || strings.EqualFold(sec, "unconfined")
	return aaWeak && secWeak
}

func noResourceLimits(c dockerInspectPosture) bool {
	if c.HostConfig.Memory > 0 || c.HostConfig.NanoCpus > 0 {
		return false
	}
	if c.HostConfig.PidsLimit != nil && *c.HostConfig.PidsLimit > 0 {
		return false
	}
	return true
}

func sensitiveMounts(c dockerInspectPosture, dataRoot string) []string {
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		for _, x := range out {
			if x == s {
				return
			}
		}
		out = append(out, shared.TruncateRunes(s, 512))
	}
	for _, b := range c.HostConfig.Binds {
		parts := strings.SplitN(b, ":", 3)
		if len(parts) >= 2 {
			if isSensitiveHostPath(parts[0], dataRoot) {
				add(parts[0] + " -> " + parts[1])
			}
		}
	}
	for _, m := range c.Mounts {
		if isSensitiveHostPath(m.Source, dataRoot) || isSensitiveHostPath(m.Destination, dataRoot) {
			add(m.Source + " -> " + m.Destination)
		}
	}
	return out
}

func isSensitiveHostPath(p, dataRoot string) bool {
	p = filepath.Clean(p)
	if p == "/" {
		return true
	}
	if p == "/etc" || strings.HasPrefix(p, "/etc/") {
		return true
	}
	if p == "/var/run/docker.sock" || strings.HasSuffix(p, "/docker.sock") {
		return true
	}
	for _, pre := range []string{"/proc", "/sys", "/dev", "/home"} {
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	dr := filepath.Clean(dataRoot)
	if dr != "." && dr != "/" && (p == dr || strings.HasPrefix(p, dr+"/")) {
		return true
	}
	return false
}

func dockerSockBindSummary(c dockerInspectPosture) string {
	for _, b := range c.HostConfig.Binds {
		if strings.Contains(b, dockerSockMountSubstr) {
			parts := strings.SplitN(b, ":", 3)
			if len(parts) >= 2 && (strings.HasSuffix(parts[0], "docker.sock") || strings.Contains(parts[0], dockerSockMountSubstr)) {
				name := strings.TrimPrefix(c.Name, "/")
				cid := c.ID
				if len(cid) > 12 {
					cid = cid[:12]
				}
				return shared.TruncateRunes(name+" ("+cid+")", 320)
			}
		}
	}
	for _, m := range c.Mounts {
		ls := strings.ToLower(m.Source + m.Destination)
		if strings.Contains(ls, dockerSockMountSubstr) {
			name := strings.TrimPrefix(c.Name, "/")
			cid := c.ID
			if len(cid) > 12 {
				cid = cid[:12]
			}
			return shared.TruncateRunes(name+" ("+cid+")", 320)
		}
	}
	return ""
}

func extractPublishedPorts(containerName, idShort string, c dockerInspectPosture) []payload.DockerPublishedPort {
	var out []payload.DockerPublishedPort
	for portProto, bindings := range c.NetworkSettings.Ports {
		containerPort, proto := splitPortProto(portProto)
		for _, b := range bindings {
			hostIP := strings.TrimSpace(b.HostIp)
			if hostIP == "" {
				hostIP = "0.0.0.0"
			}
			pp := payload.DockerPublishedPort{
				Container:         shared.TruncateRunes(containerName, 256),
				ContainerID:       shared.TruncateRunes(idShort, 64),
				HostIP:            hostIP,
				HostPort:          strings.TrimSpace(b.HostPort),
				ContainerPort:     containerPort,
				Protocol:          proto,
				BindAllInterfaces: hostBindsAll(hostIP),
			}
			out = append(out, pp)
		}
	}
	return out
}

func hostBindsAll(ip string) bool {
	ip = strings.TrimSpace(ip)
	return ip == "" || ip == "0.0.0.0" || ip == "::" || ip == "[::]"
}

func splitPortProto(s string) (port, proto string) {
	if idx := strings.LastIndex(s, "/"); idx >= 0 {
		return s[:idx], strings.TrimSpace(s[idx+1:])
	}
	return s, "tcp"
}

func overlayNetInspect(ctx context.Context, dockerPath string, out *payload.DockerPosture) {
	raw, err := runDockerOutput(ctx, dockerPath, "network", "ls", "--filter", "driver=overlay", "--format", "{{.ID}}")
	if err != nil {
		return
	}
	var ids []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			ids = append(ids, line)
		}
		if len(ids) >= dockerPostureOverlayNetCap {
			break
		}
	}
	for _, nid := range ids {
		nb, err := runDockerOutput(ctx, dockerPath, "network", "inspect", nid, "--format", "{{json .}}")
		if err != nil {
			continue
		}
		var one dockerNetworkInspectPosture
		if err := json.Unmarshal(nb, &one); err != nil {
			continue
		}
		if one.Driver != "overlay" {
			continue
		}
		enc := overlayEncrypted(one.Options)
		entry := payload.DockerOverlayNetworkEncryption{
			NetworkName: shared.TruncateRunes(one.Name, 256),
			Encrypted:   enc,
		}
		out.CustomNetworksEncrypted = append(out.CustomNetworksEncrypted, entry)
	}
}

func overlayEncrypted(opts map[string]string) bool {
	if opts == nil {
		return false
	}
	for k, v := range opts {
		if strings.Contains(strings.ToLower(k), "encrypted") && strings.TrimSpace(v) != "" {
			lv := strings.ToLower(strings.TrimSpace(v))
			return lv == "true" || lv == "1"
		}
	}
	v, ok := opts["encrypted"]
	if !ok {
		return false
	}
	lv := strings.ToLower(strings.TrimSpace(v))
	return lv == "true" || lv == "1"
}
