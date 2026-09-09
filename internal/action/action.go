//go:build linux

// Package action carries out a fix on this machine.
//
// This is the most dangerous code in the agent, so it is the narrowest. One rule
// decides its whole shape:
//
//	The service never sends a command. It names an action from this catalog and
//	fills in that action's parameters. Anything else is refused.
//
// So "ghostpsy is not a root agent that does whatever it is told" is true because
// of how this package is built, not because we promise it. Three walls stand
// between the cloud and a customer's server:
//
//  1. The action type must be in the catalog here.
//  2. Every parameter must match the exact shape the action declared for it.
//  3. Every command must already be declared in internal/privexec, which is also
//     what generates the sudo grant on the host.
//
// A fourth wall belongs to the machine owner and beats all of the above: if
// actions are switched off locally, the agent obeys the machine, not the cloud.
package action

import (
	"regexp"
	"time"

	"github.com/ghostpsy/agent-linux/internal/privexec"
)

// Mode is what the service is asking for. The words match internal/solve.
const (
	ModeDryRun = "dry_run"
	ModeRun    = "run"
)

// Reversibility says how well a change can be put back.
//
// It is declared per action and shown before anything runs, because the earlier
// rule — "no action without a backup and a rollback" — breaks on the first fix we
// ship: backing up the logs on a full disk needs the very space the fix exists to
// free. Honesty about undo is the workable rule; a promise we cannot keep is not.
type Reversibility string

const (
	// ReverseFull means putting it back is cheap and reliable.
	ReverseFull Reversibility = "full"
	// ReversePartial means it can be recovered, but it costs something or
	// depends on something — a registry being up, a mirror still carrying a
	// version. The action must name what it depends on in UndoWhy.
	ReversePartial Reversibility = "partial"
	// ReverseNone means truly gone. The dry run is then the only safety net,
	// and the screen has to say exactly that.
	ReverseNone Reversibility = "none"
)

// BackupKind says what a backup of an action would even be.
type BackupKind string

const (
	// BackupNone means there is nothing to copy: the action records what it
	// needs to reverse itself, or it cannot be reversed at all.
	BackupNone BackupKind = "none"

	// BackupCopyFiles copies small files aside before they are edited. This is
	// the cheap, reliable case — a config file is a few kilobytes.
	BackupCopyFiles BackupKind = "copy_files"

	// BackupArchiveFreed would need as many bytes as the action frees, which is
	// why it usually cannot happen. Writing it would cause the exact problem the
	// action exists to solve, so the free space is measured at the moment of
	// running and the backup is refused out loud when it does not fit.
	BackupArchiveFreed BackupKind = "archive_freed"
)

// BackupPlan is how an action would be backed up, if it can be.
type BackupPlan struct {
	Kind BackupKind

	// Target is the filesystem the archive would be written to, for
	// BackupArchiveFreed. It is the disk being freed, which is the whole problem.
	Target string

	// Freed matches the size a dry run says would be freed, so the space needed
	// can be measured rather than guessed. Required for BackupArchiveFreed.
	Freed *regexp.Regexp
}

// Param is one value the service fills in.
type Param struct {
	Name string

	// Why says in plain words what may go here. It reaches the approval screen.
	Why string

	// Allow is the only shape accepted, anchored so it matches whole values.
	// Checked here, and checked again by privexec when the command is built.
	Allow *regexp.Regexp
}

// CheckID names a judgement the runner makes itself, rather than a command.
type CheckID string

const (
	// CheckPlanKeepsMeReachable reads the dry run's own output and refuses a
	// plan whose rules would not allow a port somebody is connected on right
	// now. It runs before anything changes, which is the only place a lock-out
	// can actually be prevented rather than repaired.
	CheckPlanKeepsMeReachable CheckID = "plan_keeps_me_reachable"

	// CheckKeepsMeReachable runs after the change and fails if the machine
	// stopped answering, which is what triggers the undo. Together with the one
	// above it is the entire risk of the firewall and ssh actions: switching on
	// a firewall on a remote server is how people lose access to their own
	// machine for good.
	CheckKeepsMeReachable CheckID = "keeps_me_reachable"

	// CheckUnitNotProtected refuses to touch a service the machine's owner
	// listed as hands off. It runs first, so a protected service is never
	// touched at all — not even for a moment.
	CheckUnitNotProtected CheckID = "unit_not_protected"

	// CheckSomebodyCanStillLogIn refuses a hardening change that would leave
	// nobody able to log in.
	//
	// The other reachability checks ask whether the port still answers. That is
	// not the same question, and the difference locked me out of a real machine:
	// `PermitRootLogin no` on a cloud image left sshd running and port 22
	// accepting every connection, then refusing every login. This one counts
	// accounts instead of ports.
	CheckSomebodyCanStillLogIn CheckID = "somebody_can_still_log_in"

	// CheckServiceIsOneWeConfigure refuses to restart a service ghostpsy does not
	// configure, and hands over the commands instead.
	//
	// The rule is not only about the sudo grant. We cannot see what nginx is
	// serving or what a restart of it interrupts, so "systemd says it failed, so
	// restart it" is a guess dressed up as a fix. Where we wrote the configuration
	// we know what changed and why; where we did not, the honest answer is the
	// command and a look at the status first.
	CheckServiceIsOneWeConfigure CheckID = "service_is_one_we_configure"

	// CheckDropInWillTakeEffect refuses a change that would be written and then
	// ignored, and hands over the commands to make it by hand instead.
	//
	// sshd keeps the first value it reads for a keyword. A server whose main
	// configuration sets this directive above its Include line would read our file
	// and take no notice of it — so we would write it, report success, and change
	// nothing. That is the worst outcome available to a tool whose whole claim is
	// that you can see what it did.
	CheckDropInWillTakeEffect CheckID = "drop_in_will_take_effect"

	// CheckSettingTookEffect reads what the service reported and refuses to call the
	// fix done unless the value is really there.
	//
	// `sshd -T` exiting zero only means sshd answered. Treating that as success is how
	// a fix reports done and changed nothing.
	CheckSettingTookEffect CheckID = "setting_took_effect"

	// CheckFirewallIsStillOff reads a `ufw status` printed a moment earlier and
	// refuses to carry on if the firewall is now enforcing.
	//
	// It exists so the step before the rules can safely put ufw's own record
	// straight. ufw keeps two answers to "am I on": ENABLED in /etc/ufw/ufw.conf,
	// and whether its chains are in the kernel. When those disagree — enabled on
	// paper, enforcing nothing — `ufw allow` dies with a message that names no
	// command at all:
	//
	//	$ sudo ufw allow 22/tcp
	//	ERROR: problem running
	//
	// Switching it off first makes the record honest and takes no protection
	// away, because there was none. That is only true while it really is off, and
	// this is what makes sure of it.
	CheckFirewallIsStillOff CheckID = "firewall_is_still_off"
)

// checks is every judgement the runner knows how to make. A step naming anything
// else is refused at startup.
var checks = map[CheckID]bool{
	CheckPlanKeepsMeReachable:    true,
	CheckKeepsMeReachable:        true,
	CheckUnitNotProtected:        true,
	CheckSomebodyCanStillLogIn:   true,
	CheckServiceIsOneWeConfigure: true,
	CheckDropInWillTakeEffect:    true,
	CheckSettingTookEffect:       true,
	CheckFirewallIsStillOff:      true,
}

// Step is one thing a phase does.
//
// Exactly one of Command or Check is set. A step cannot name a binary of its
// own: a privileged command has to already be declared in privexec, which is
// also what writes the sudo grant, so the two cannot drift apart.
type Step struct {
	// Why says what this step is for, in plain words. It is shown next to the
	// command in the output the customer reads.
	Why string

	Command privexec.ID
	Check   CheckID

	// Args gives the command's parameters their values. A value is either a
	// literal or {name}, naming one of the action's own parameters.
	Args map[string]string

	// Reads marks a step that only looks at the machine and changes nothing.
	//
	// It decides whether a failed run gets put back. A run phase that read the
	// machine and then stopped at a check has changed nothing, and undoing it
	// makes the undo the thing that does the damage: a job that stopped at "the
	// firewall is already on" switched off a firewall that was working, because
	// the read before the check counted as something having happened.
	//
	// A step is a change unless it says otherwise. Forgetting to mark a read
	// leaves the undo running exactly as it did before, which is the safe way to
	// be wrong.
	Reads bool
}

// Variant is one way of carrying out an action on one kind of machine.
//
// Turning on a firewall is ufw on Debian and firewalld on the RHEL family. The
// agent picks, not the cloud: the machine knows what it has installed, and
// keeping the choice here keeps the vocabulary the service speaks small.
type Variant struct {
	// Needs is the binary that must be installed for this variant to apply.
	// Empty means it applies anywhere.
	Needs string

	// DryRun changes nothing. It is required — see checkAction.
	DryRun []Step
	Run    []Step
	Verify []Step

	// Undo must be absent when the action says it cannot be undone. A rollback
	// step on an irreversible action is a button that lies.
	Undo []Step

	// Backup is how this variant would be backed up. It belongs here rather than
	// on the action because two ways of doing the same fix can differ: switching
	// on automatic updates edits a file on Debian and flips a timer on the RHEL
	// family, and only one of those has anything to copy.
	Backup BackupPlan
}

// Action is one fix, declared as data.
type Action struct {
	Type string

	// Summary is what the approval screen says this will do, in plain words. It
	// may contain {name} to name a parameter.
	Summary string

	Params        []Param
	Reversibility Reversibility

	// UndoWhy explains the reversibility in plain words: "the file is copied
	// before editing", "deleted logs cannot be brought back", "the images can be
	// pulled again from your registry".
	UndoWhy string

	// Settle is how long to wait after the change before checking it worked. A
	// service restarted a moment ago is not yet proof of anything.
	Settle time.Duration

	Variants []Variant
}

// stepTimeout bounds one command. Long enough for a package install on a slow
// mirror, short enough that a hung fix does not hold the machine all day.
const stepTimeout = 10 * time.Minute
