//go:build linux

package collect

import (
	"context"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

type ActionEventObserver func(event ActionEvent)

type ActionEvent struct {
	Action string
	Phase  string
	Items  int
	Error  string
}

// Stub builds a v1 payload (listeners include firewall_rule; other blocks optional).
func Stub(machineUUID string, scanSeq int) payload.V1 {
	v, _ := StubWithObserver(context.Background(), machineUUID, scanSeq, nil)
	return v
}

// StubWithObserver builds a v1 payload and calls observe before each data collection action.
// Pass a cancellable context (e.g. signal.NotifyContext) to abort a long scan; returns ctx.Err() when cancelled between steps.
func StubWithObserver(ctx context.Context, machineUUID string, scanSeq int, observe ActionEventObserver) (payload.V1, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	return stubBuildPayloadV1(ctx, machineUUID, scanSeq, observe)
}

func hostNetworkErr(hn *payload.HostNetwork) string {
	if hn == nil {
		return ""
	}
	return hn.Error
}

func hostDiskErr(hd *payload.HostDisk) string {
	if hd == nil {
		return ""
	}
	return hd.Error
}

func hostUsersErr(hus *payload.HostUsersSummary) string {
	if hus == nil {
		return ""
	}
	return hus.Error
}

func hostSSHErr(hs *payload.HostSSH) string {
	if hs == nil {
		return ""
	}
	return hs.Error
}

func packagesUpdatesErr(pu *payload.PackagesUpdates) string {
	if pu == nil {
		return ""
	}
	return pu.Error
}

func hostNetworkInterfaces(hn *payload.HostNetwork) []payload.NetworkIface {
	if hn == nil {
		return nil
	}
	return hn.Interfaces
}

func hostDiskFilesystems(hd *payload.HostDisk) []payload.FilesystemEntry {
	if hd == nil {
		return nil
	}
	return hd.Filesystems
}

func hostUsersSample(hus *payload.HostUsersSummary) []payload.UserSample {
	if hus == nil {
		return nil
	}
	return hus.Sample
}

func hostSSHListenCount(hs *payload.HostSSH) int {
	if hs == nil {
		return 0
	}
	return len(hs.ListenAddresses)
}

func shadowNotifyCount(s *payload.ShadowAccountSummary) int {
	if s == nil || !s.ShadowReadable {
		return 0
	}
	return 1
}

func shadowNotifyError(s *payload.ShadowAccountSummary) string {
	if s == nil {
		return ""
	}
	return s.Error
}

func duplicateIDNotifyCount(d *payload.DuplicateUidGid) int {
	if d == nil {
		return 0
	}
	return d.DuplicateUidCount + d.DuplicateGidCount
}

func passwordPolicyNotifyCount(p *payload.PasswordPolicyFingerprint) int {
	if p == nil {
		return 0
	}
	return len(p.PwqualityKeys) + len(p.PamPasswordRequisiteLines)
}

func pathPermissionsNotifyCount(p *payload.PathPermissionsAudit) int {
	if p == nil {
		return 0
	}
	n := len(p.WorldWritableDirsSample) + len(p.SgidItemsSample) + len(p.UnownedFilesSample)
	if p.TmpStickyBitPresent != nil {
		n++
	}
	return n
}

func tcpWrappersNotifyCount(t *payload.TcpWrappersFingerprint) int {
	if t == nil {
		return 0
	}
	return t.HostsAllowLineCount + t.HostsDenyLineCount
}

func legacyInsecureNotifyCount(l *payload.LegacyInsecureServices) int {
	if l == nil {
		return 0
	}
	n := 0
	if l.TelnetSuspected {
		n++
	}
	if l.RshSuspected {
		n++
	}
	if l.RloginSuspected {
		n++
	}
	if l.RexecSuspected {
		n++
	}
	if l.VsftpdSuspected {
		n++
	}
	if l.ProftpdSuspected {
		n++
	}
	if l.InetdConfPresent {
		n++
	}
	return n
}

func packagesPendingUpdatesCount(pu *payload.PackagesUpdates) int {
	if pu == nil {
		return 0
	}
	return pu.PendingUpdatesCount
}

func hostBackupLogError(hb *payload.HostBackup) string {
	if hb == nil {
		return "No backup information could be extracted."
	}
	if hb.Error != "" {
		return hb.Error
	}
	if hb.BackupStatus == "on" {
		return ""
	}
	return "No backup found."
}

func nonEmptyOSInfoFields(osInfo payload.OSInfo) int {
	fields := []string{
		osInfo.Pretty,
		osInfo.Kernel,
		osInfo.KernelArch,
		osInfo.DistroID,
		osInfo.DistroName,
		osInfo.DistroVersionID,
		osInfo.OSReleaseID,
		osInfo.OSReleaseVersionID,
		osInfo.OSReleaseVersion,
		osInfo.OSReleaseName,
		osInfo.Platform,
		osInfo.PlatformFamily,
		osInfo.PlatformVersion,
	}
	count := 0
	for _, field := range fields {
		if field != "" {
			count++
		}
	}
	return count
}

func firewallRuleCount(fw *payload.Firewall) int {
	if fw == nil || fw.RuleCount == nil {
		return 0
	}
	return *fw.RuleCount
}

func firewallError(fw *payload.Firewall) string {
	if fw == nil {
		return "No firewall information could be extracted."
	}
	return fw.Error
}

func grubNotifyCount(g *payload.GrubSnapshot) int {
	if g == nil {
		return 0
	}
	if g.GrubCmdlineLinux != "" || g.GrubCfgReadablePath != "" {
		return 1
	}
	return 0
}

func firmwareNotifyCount(f *payload.FirmwareBoot) int {
	if f == nil {
		return 0
	}
	if f.BootMode != "unknown" {
		return 1
	}
	return 0
}

func systemdNotifyCount(s *payload.SystemdHealth) int {
	if s == nil || !s.SystemdPresent {
		return 0
	}
	return 1
}

func selinuxNotifyCount(m *payload.SelinuxApparmorBlock) int {
	if m == nil {
		return 0
	}
	if m.SelinuxMode != "" || m.ApparmorSummary != "" {
		return 1
	}
	return 0
}

func webDbServersNotifyCount(w *payload.WebDbServersFingerprint) int {
	if w == nil {
		return 0
	}
	n := 0
	if w.NginxServerTokens != "" || w.NginxConfigPathUsed != "" {
		n++
	}
	if w.ApacheServerTokens != "" || w.ApacheConfigPathUsed != "" {
		n++
	}
	if w.MysqlBindAddress != "" || w.MysqlConfigPathUsed != "" {
		n++
	}
	if w.PostgresqlListenAddresses != "" || w.PostgresqlConfigPathUsed != "" {
		n++
	}
	return n
}

func redisExposureNotifyCount(r *payload.RedisExposureFingerprint) int {
	if r == nil {
		return 0
	}
	if r.ConfigPathUsed != "" || r.UnitActiveState != "" {
		return 1
	}
	return 0
}

func cronTimersNotifyCount(c *payload.CronTimersInventory) int {
	if c == nil {
		return 0
	}
	return c.SystemCrontabLineCount + c.UserCrontabsPresentCount + c.SystemdTimersCount
}

func cupsExposureNotifyCount(c *payload.CupsExposureFingerprint) int {
	if c == nil {
		return 0
	}
	if len(c.ListenLinesSample)+len(c.WebInterfaceLinesSample) > 0 || c.UnitActiveState != "" {
		return 1
	}
	return 0
}

func mtaNotifyCount(m *payload.MtaFingerprint) int {
	if m == nil {
		return 0
	}
	if m.DetectedMta != "" && m.DetectedMta != "none" {
		return 1
	}
	return 0
}

func apacheHttpdNotifyCount(a *payload.ApacheHttpdPosture) int {
	if a == nil || !a.Detected {
		return 0
	}
	return 1
}

func apacheHttpdError(a *payload.ApacheHttpdPosture) string {
	if a == nil {
		return ""
	}
	return a.Error
}

func nginxPostureNotifyCount(n *payload.NginxPosture) int {
	if n == nil || !n.Detected {
		return 0
	}
	return 1
}

func nginxPostureError(n *payload.NginxPosture) string {
	if n == nil {
		return ""
	}
	return n.Error
}

func postfixPostureNotifyCount(p *payload.PostfixPosture) int {
	if p == nil || !p.Detected {
		return 0
	}
	return 1
}

func postfixPostureError(p *payload.PostfixPosture) string {
	if p == nil {
		return ""
	}
	return p.Error
}

func mysqlPostureNotifyCount(m *payload.MysqlPosture) int {
	if m == nil || !m.Detected {
		return 0
	}
	return 1
}

func mysqlPostureError(m *payload.MysqlPosture) string {
	if m == nil {
		return ""
	}
	return m.Error
}

func postgresPostureNotifyCount(p *payload.PostgresPosture) int {
	if p == nil || !p.Detected {
		return 0
	}
	return 1
}

func postgresPostureError(p *payload.PostgresPosture) string {
	if p == nil {
		return ""
	}
	return p.Error
}

func dockerPostureNotifyCount(d *payload.DockerPosture) int {
	if d == nil || !d.Detected {
		return 0
	}
	return 1
}

func dockerPostureError(d *payload.DockerPosture) string {
	if d == nil {
		return ""
	}
	return d.Error
}

// softwarePackagesHostRuntimes is §5 only: interpreter `items` (and optional collection error).
// Docker/kubelet fingerprints are emitted only under container_and_cloud_native_linux.
// Always emit host_runtimes when the collector ran (including items: [] on minimal hosts) for stable ingest and CI payload checks.
func softwarePackagesHostRuntimes(hr *payload.HostRuntimes) *payload.HostRuntimes {
	if hr == nil {
		return nil
	}
	items := hr.Items
	if items == nil {
		items = []payload.RuntimeEntry{}
	}
	return &payload.HostRuntimes{
		Items: items,
		Error: hr.Error,
	}
}

// containerCloudHostRuntimes is §6 only: Docker and kubelet fingerprints (no language `items` key).
// Omit the whole block when there is no Docker or kubelet signal (JSON {} for the component).
func containerCloudHostRuntimes(hr *payload.HostRuntimes) *payload.ContainerNativeHostRuntimes {
	if hr == nil || (hr.Docker == nil && hr.Kubelet == nil) {
		return nil
	}
	return &payload.ContainerNativeHostRuntimes{
		Docker:  hr.Docker,
		Kubelet: hr.Kubelet,
	}
}

// containerWorkloadsNotifyCount totals the Docker + kubelet workload rows
// for the action notify log, so the scan pipeline can surface "N workloads"
// alongside other inventory counts.
func containerWorkloadsNotifyCount(w *payload.ContainerWorkloads) int {
	if w == nil {
		return 0
	}
	return len(w.DockerContainers) + len(w.KubeletPods)
}

func loggingAuditNotifyCount(c payload.LoggingAndSystemAuditingComponent) int {
	n := 0
	if c.SyslogForwarding != nil {
		n += len(c.SyslogForwarding.Daemons)
	}
	if c.Journald != nil {
		n++
	}
	if c.Auditd != nil {
		n++
	}
	if c.LogrotateDisk != nil {
		n++
	}
	if c.AtBatch != nil {
		n++
	}
	if c.ProcessAccounting != nil {
		n++
	}
	return n
}

func securityFrameworksNotifyCount(c payload.SecurityFrameworksAndMalwareDefenseComponent) int {
	n := 0
	if p := c.MacDeepPosture; p != nil {
		if p.SelinuxPsZLineSampleCap != nil || len(p.SelinuxSemanagePermissiveSample) > 0 ||
			p.ApparmorProfilesEnforceCount != nil || p.ApparmorProfilesComplainCount != nil ||
			p.SelinuxSemanageUnavailable != "" || p.ApparmorStatusUnavailable != "" || p.Error != "" {
			n++
		}
	}
	if c.MalwareScannersPosture != nil {
		n += len(c.MalwareScannersPosture.Scanners)
		if c.MalwareScannersPosture.Error != "" {
			n++
		}
	}
	if f := c.Fail2banPosture; f != nil {
		if f.Present || f.Error != "" {
			n++
		}
	}
	return n
}

func securityFrameworksFirstError(c payload.SecurityFrameworksAndMalwareDefenseComponent) string {
	if c.MacDeepPosture != nil && c.MacDeepPosture.Error != "" {
		return c.MacDeepPosture.Error
	}
	if c.MalwareScannersPosture != nil && c.MalwareScannersPosture.Error != "" {
		return c.MalwareScannersPosture.Error
	}
	if c.Fail2banPosture != nil && c.Fail2banPosture.Error != "" {
		return c.Fail2banPosture.Error
	}
	return ""
}

func cryptographyNotifyCount(c payload.CryptographyComponent) int {
	inv := c.LocalTlsCertInventory
	if inv == nil {
		return 0
	}
	if len(inv.Items) > 0 {
		return len(inv.Items)
	}
	if inv.FilesScanned > 0 || inv.Error != "" {
		return 1
	}
	return 0
}

func loggingAuditFirstError(c payload.LoggingAndSystemAuditingComponent) string {
	if c.SyslogForwarding != nil && c.SyslogForwarding.Error != "" {
		return c.SyslogForwarding.Error
	}
	if c.Journald != nil && c.Journald.Error != "" {
		return c.Journald.Error
	}
	if c.Auditd != nil && c.Auditd.Error != "" {
		return c.Auditd.Error
	}
	if c.LogrotateDisk != nil && c.LogrotateDisk.Error != "" {
		return c.LogrotateDisk.Error
	}
	if c.AtBatch != nil && c.AtBatch.Error != "" {
		return c.AtBatch.Error
	}
	if c.ProcessAccounting != nil && c.ProcessAccounting.Error != "" {
		return c.ProcessAccounting.Error
	}
	return ""
}
