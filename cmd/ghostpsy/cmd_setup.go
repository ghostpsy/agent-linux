//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghostpsy/agent-linux/internal/agentconfig"
	"github.com/ghostpsy/agent-linux/internal/service"
	"github.com/ghostpsy/agent-linux/internal/state"
)

// installSudoRule writes the privilege grant, but only after the system's own
// checker has accepted it.
//
// This is the single most dangerous step in the whole install. A malformed file
// in /etc/sudoers.d can lock every administrator out of sudo on the host, and
// the way back in is a rescue boot. So the rule is written to a temporary file,
// checked with visudo, and only then moved into place.
func installSudoRule(dest, rule string, run runner) error {
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".ghostpsy-sudoers-*")
	if err != nil {
		return fmt.Errorf("could not prepare the sudo rule: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.WriteString(rule); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("could not write the sudo rule: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("could not write the sudo rule: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o440); err != nil {
		return fmt.Errorf("could not set permissions on the sudo rule: %w", err)
	}

	if err := run("visudo", "-c", "-f", tmpPath); err != nil {
		// Deliberately keep the rejected file: it is the only evidence of what
		// went wrong, and this is a bug in ghostpsy, not on the user's server.
		kept := dest + ".rejected"
		_ = os.Rename(tmpPath, kept)
		return fmt.Errorf("the sudo rule did not pass this system's own check, so it was not installed. "+
			"Your sudo setup is untouched. Please send us this file: %s (%w)", kept, err)
	}

	if err := os.Rename(tmpPath, dest); err != nil {
		return fmt.Errorf("could not install the sudo rule: %w", err)
	}
	return os.Chmod(dest, 0o440)
}

// checkSudoersIncludesDropInDir refuses to continue when /etc/sudoers does not
// read the drop-in directory.
//
// Very old sudo ignores /etc/sudoers.d unless the #includedir line is present.
// A grant that looks installed but is never read is worse than no grant,
// because nothing reports it: the agent would simply lose half its data and
// say nothing.
func checkSudoersIncludesDropInDir(sudoersPath string) error {
	b, err := os.ReadFile(sudoersPath)
	if err != nil {
		return fmt.Errorf("could not read %s: %w", sudoersPath, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#includedir") || strings.HasPrefix(line, "@includedir") {
			return nil
		}
	}
	return errors.New("this server's /etc/sudoers has no #includedir line, so a rule placed in " +
		"/etc/sudoers.d would never be read. Add `#includedir /etc/sudoers.d` with visudo, then run this again")
}

type runner func(name string, args ...string) error

// installSudoCommands maps a package manager to the command that installs sudo.
// The list is explicit rather than guessed: running an invented command as root
// on someone's server is not something to improvise.
var installSudoCommands = map[string][]string{
	"apt-get": {"apt-get", "install", "-y", "sudo"},
	"dnf":     {"dnf", "install", "-y", "sudo"},
	"yum":     {"yum", "install", "-y", "sudo"},
	"zypper":  {"zypper", "--non-interactive", "install", "sudo"},
	"apk":     {"apk", "add", "--no-cache", "sudo"},
	"pacman":  {"pacman", "-S", "--noconfirm", "sudo"},
}

// ensureSudo makes sure sudo is present, installing it if it is not.
//
// sudo is the mechanism the entire privilege model stands on: the agent reads
// privileged files through it and runs as an unprivileged user otherwise. There
// is no root mode to fall back to, so if this fails the install stops.
//
// In practice the two failure conditions barely overlap. Hosts that lack sudo
// are modern enough for their package manager to work; hosts whose repositories
// are dead are old enough to have shipped sudo already.
func ensureSudo(present func() bool, packageManager string, run runner) error {
	if present() {
		return nil
	}

	argv, known := installSudoCommands[packageManager]
	if !known {
		return errors.New("sudo is not installed on this server and there is no package manager here that " +
			"ghostpsy knows how to use. Install sudo, then run this again. ghostpsy never runs as root, " +
			"so it cannot continue without it")
	}

	if err := run(argv[0], argv[1:]...); err != nil {
		return fmt.Errorf("could not install sudo with %s. This server's package repositories may no longer "+
			"be online, which is a property of the server rather than of ghostpsy. Install sudo yourself, "+
			"then run this again (%w)", packageManager, err)
	}
	return nil
}

// setupStep is one thing the installer does, with the sentence the user sees.
//
// The description is not decoration. Installing this means creating a user and
// granting sudo rights on someone's server, and they are entitled to read the
// list before it happens — that is what --dry-run prints.
type setupStep struct {
	describe string
	do       func() error
}

// runSetupSteps performs the install, or just describes it.
//
// A failing step stops everything. Carrying on would leave the server
// half-configured, which is harder to reason about than not installed at all.
func runSetupSteps(out io.Writer, steps []setupStep, dryRun bool) error {
	if dryRun {
		_, _ = fmt.Fprint(out, "This is what would happen. Nothing is being changed.\n\n")
		for _, s := range steps {
			_, _ = fmt.Fprintf(out, "  - %s\n", s.describe)
		}
		_, _ = fmt.Fprintln(out, "\nRun the same command without --dry-run to do it.")
		return nil
	}

	for _, s := range steps {
		if err := s.do(); err != nil {
			return fmt.Errorf("%s: %w", s.describe, err)
		}
		_, _ = fmt.Fprintf(out, "  ok  %s\n", s.describe)
	}
	return nil
}

// createAgentUser makes the locked system account the agent runs as.
//
// It cannot log in and has no password. Creating a user that already exists is
// normal on a re-run, not a failure: the installer has to be safe to run twice.
func createAgentUser(exists func() bool, run runner) error {
	if exists() {
		return nil
	}
	err := run("useradd",
		"--system",
		"--shell", "/usr/sbin/nologin",
		"--home-dir", agentStateDir,
		agentUser,
	)
	if err != nil {
		return fmt.Errorf("could not create the %s user: %w", agentUser, err)
	}
	return nil
}

// agentStateDir is where the agent keeps its own state, owned by the agent user.
const agentStateDir = "/var/lib/ghostpsy"

// serviceEnv is what the running service has to be told, and nothing more.
//
// The address is known while setup runs and forgotten by the time the service
// starts, so a machine registered against a staging or self-hosted server would
// then report to the public one. Only a non-default address is written down:
// putting the public URL into every unit would pin thousands of servers to a
// value that is meant to stay a compiled-in default.
func serviceEnv(apiBaseURL string) []string {
	if apiBaseURL == "" || apiBaseURL == defaultAPIBaseURL {
		return nil
	}
	return []string{"GHOSTPSY_API_URL=" + apiBaseURL}
}

func newSetupCommand() *cobra.Command {
	var token string
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Create the ghostpsy user, grant scoped sudo, and start the service",
		Long: "Finishes the install once the agent binary is in place.\n\n" +
			"Creates the locked ghostpsy user, installs the sudo rule this server\n" +
			"needs, registers the machine and starts the background service.\n\n" +
			"Use --dry-run to see every change first, without making any.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSetup(cmd, token, dryRun)
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "the single-use code from the dashboard")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print every change and make none")
	return cmd
}

func runSetup(cmd *cobra.Command, token string, dryRun bool) error {
	out := cmd.OutOrStdout()

	kind := service.Detect()
	manager, err := service.For(kind)
	if err != nil {
		return err
	}

	self, err := resolveSelfPath()
	if err != nil {
		return fmt.Errorf("could not find the agent binary: %w", err)
	}

	steps := []setupStep{
		{
			describe: "Install sudo, if this server does not have it",
			do: func() error {
				return ensureSudo(func() bool { return commandExists("sudo") }, detectPackageManager(), runCommand)
			},
		},
		{
			describe: "Check that /etc/sudoers reads /etc/sudoers.d",
			do:       func() error { return checkSudoersIncludesDropInDir("/etc/sudoers") },
		},
		{
			describe: fmt.Sprintf("Create the locked %s system user", agentUser),
			do:       func() error { return createAgentUser(func() bool { return userExists(agentUser) }, runCommand) },
		},
		{
			describe: fmt.Sprintf("Create %s, owned by %s", agentStateDir, agentUser),
			do:       func() error { return createAgentStateDir() },
		},
		{
			describe: "Install the sudo rule, after checking it with visudo",
			do:       func() error { return installSudoRule(installedGrantPath, sudoersFile(), runCommand) },
		},
		{
			describe: "Register this machine",
			do:       func() error { return registerMachine(token) },
		},
		{
			// register runs as root and writes the token and the state file
			// 0600 root-owned, but the service runs as ghostpsy. Without this
			// the agent cannot read its own credentials, every heartbeat fails,
			// and the machine looks dead while the daemon retries forever.
			describe: fmt.Sprintf("Give the agent its files to %s", agentUser),
			do: func() error {
				uid, gid, err := agentUIDGID()
				if err != nil {
					return err
				}
				return giveAgentItsFiles(agentOwnedPaths(), uid, gid, os.Chown)
			},
		},
		{
			describe: fmt.Sprintf("Start the ghostpsy service (%s)", kind),
			do: func() error {
				return manager.Install(service.Spec{
					ExecStart: self + " serve",
					User:      agentUser,
					Env:       serviceEnv(envOr("GHOSTPSY_API_URL", defaultAPIBaseURL)),
				})
			},
		},
	}

	if err := runSetupSteps(out, steps, dryRun); err != nil {
		return err
	}
	if dryRun {
		return nil
	}

	_, _ = fmt.Fprintf(out, "\nDone. This server is now reporting.\n")
	_, _ = fmt.Fprintf(out, "  Runs as  %s, not root\n", agentUser)
	_, _ = fmt.Fprintf(out, "  Rights   %s\n", installedGrantPath)
	return nil
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func userExists(name string) bool {
	_, err := user.Lookup(name)
	return err == nil
}

// detectPackageManager returns the first known package manager on this host, or
// an empty string. The order matters only where two are installed, which is
// rare and harmless: any of them can install sudo.
func detectPackageManager() string {
	for _, name := range []string{"apt-get", "dnf", "yum", "zypper", "apk", "pacman"} {
		if commandExists(name) {
			return name
		}
	}
	return ""
}

func createAgentStateDir() error {
	if err := os.MkdirAll(agentStateDir, 0o750); err != nil {
		return fmt.Errorf("could not create %s: %w", agentStateDir, err)
	}
	u, err := user.Lookup(agentUser)
	if err != nil {
		return fmt.Errorf("the %s user does not exist: %w", agentUser, err)
	}
	uid, gid := atoiOrZero(u.Uid), atoiOrZero(u.Gid)
	if err := os.Chown(agentStateDir, uid, gid); err != nil {
		return fmt.Errorf("could not give %s to %s: %w", agentStateDir, agentUser, err)
	}
	return nil
}

// agentOwnedPaths is every path the installer creates as root that the service,
// running as the agent user, has to be able to read.
//
// One list, because the alternative was found the hard way twice: the token was
// missed first, then the state file. A machine whose agent cannot read one of
// these does not fail loudly — it restarts forever while the installer reports
// success.
func agentOwnedPaths() []string {
	return []string{
		filepath.Dir(agentconfig.Path()),
		agentconfig.Path(),
		agentStateDir,
		state.Path(),
	}
}

// agentUIDGID resolves the account the service runs as.
func agentUIDGID() (uid, gid int, err error) {
	u, err := user.Lookup(agentUser)
	if err != nil {
		return 0, 0, fmt.Errorf("the %s user does not exist: %w", agentUser, err)
	}
	return atoiOrZero(u.Uid), atoiOrZero(u.Gid), nil
}

// giveAgentItsFiles hands the paths to the agent account.
//
// They are created by `register`, which runs as root. The service does not, so
// without this it cannot read what it was just given.
func giveAgentItsFiles(paths []string, uid, gid int, chown func(string, int, int) error) error {
	for _, path := range paths {
		if err := chown(path, uid, gid); err != nil {
			return fmt.Errorf("could not give %s to %s: %w", path, agentUser, err)
		}
	}
	return nil
}

func atoiOrZero(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// registerMachine runs the existing register command as a child process, for
// the same reason serve does: it calls os.Exit on failure.
func registerMachine(token string) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("no code was given. Copy the command from the dashboard, which includes it")
	}
	self, err := resolveSelfPath()
	if err != nil {
		return err
	}
	out, err := exec.Command(self, "register", "--bootstrap="+token).CombinedOutput()
	if err != nil {
		return explainRegisterFailure(errors.New(strings.TrimSpace(lastLine(out))))
	}
	return nil
}

// explainRegisterFailure turns whatever registration reported into something a
// busy sysadmin can act on.
//
// On a real host this step produced:
//
//	register: post: Post "https://api.ghostpsy.com/...": local error: tls: bad record MAC
//
// which says nothing useful to the person who has to fix it. The two things
// that actually go wrong here need different answers, so they get different
// messages.
func explainRegisterFailure(err error) error {
	detail := err.Error()
	lower := strings.ToLower(detail)

	switch {
	case strings.Contains(lower, "401"), strings.Contains(lower, "token"), strings.Contains(lower, "rejected"):
		return fmt.Errorf("the code from the dashboard was not accepted. It works once and stops working "+
			"after 24 hours, so get a fresh one from the Add machine screen and run this again (%s)", detail)
	case strings.Contains(lower, "already registered"):
		// Nothing was sent. Registration stopped at a check on this machine, so
		// the network is not involved and must not be blamed. Re-running the
		// installer is what a person does to upgrade, which makes this one of the
		// messages they are most likely to see.
		return fmt.Errorf("this server is already registered with ghostpsy, so it was left as it is. " +
			"To upgrade the agent, use `ghostpsy update`. To attach this server to a different " +
			"organization, run setup again with --force")
	case serverAnswered(detail):
		// Telling someone to inspect a firewall that is working perfectly is
		// worse than saying nothing. The server's own words are the only thing
		// here that identifies which rule was hit, so they are kept.
		return fmt.Errorf("the ghostpsy service refused this machine. Nothing is wrong with this "+
			"server's network — the service answered and declined. What it said: %s", detail)
	default:
		return fmt.Errorf("could not reach the ghostpsy service to register this machine. Check that this "+
			"server can make outbound HTTPS connections to api.ghostpsy.com, then run this again (%s)", detail)
	}
}

// serverAnswered reports whether the failure carries an HTTP status line.
//
// A status means the request arrived and was answered, which rules out every
// network explanation. Matching on the word "Response" plus a 4xx or 5xx keeps
// it to what the agent itself prints, rather than guessing at arbitrary text.
func serverAnswered(detail string) bool {
	if !strings.Contains(detail, "Response:") {
		return false
	}
	for _, code := range []string{" 4", " 5"} {
		if idx := strings.Index(detail, "Response:"); idx >= 0 {
			rest := detail[idx+len("Response:"):]
			if strings.HasPrefix(rest, code) {
				return true
			}
		}
	}
	return false
}

func runCommand(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}
