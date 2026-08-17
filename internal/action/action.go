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
)

// checks is every judgement the runner knows how to make. A step naming anything
// else is refused at startup.
var checks = map[CheckID]bool{
	CheckPlanKeepsMeReachable: true,
	CheckKeepsMeReachable:     true,
	CheckUnitNotProtected:     true,
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
