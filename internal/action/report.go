//go:build linux

package action

import "github.com/ghostpsy/agent-linux/internal/privexec"

// The report is the only thing the service ever learns about what happened on the
// machine, and through it the only thing the customer ever sees. So it carries the
// real output, the real exit codes and the honest ledger — not a summary we chose.

// Request is one action the service asked for.
type Request struct {
	Type   string            `json:"type"`
	Params map[string]string `json:"params,omitempty"`
}

// Job is what the service handed over.
type Job struct {
	Mode    string    `json:"mode"`
	Actions []Request `json:"actions"`

	// Backup is true when the person asked for one. It is a request, not an
	// instruction: whether one is possible is measured on the machine.
	Backup bool `json:"backup"`
}

// CommandRun is one command, exactly as it ran.
type CommandRun struct {
	Why      string `json:"why"`
	Display  string `json:"display"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	Millis   int64  `json:"duration_ms"`

	// Advice is set by a step that refused a change as too dangerous, and carries
	// the way to make it by hand. The runner lifts it onto the action so the app
	// does not have to hunt for it among the commands.
	Advice *DoItYourself `json:"-"`

	// id is the command that produced this run, for a later check that reads what an
	// earlier step printed — see outputOf.
	//
	// Unexported, so it never reaches the wire: the app has no use for our internal
	// ids. It exists because the alternative was matching on Display, and Display is
	// a sentence written for a person, with the arguments filled in. Rewriting it to
	// compare would only work for a command that takes no arguments.
	id privexec.ID
}

// DoItYourself is a change ghostpsy refused to make, with the way to make it.
//
// It exists because refusing is not the same as helping. Somebody who asked for a
// change still wants it, and if all we say is no, they go and do it from memory
// without the one check that would have saved them. So the refusal carries the
// risk, the thing to confirm first, and the commands — ready to paste.
type DoItYourself struct {
	Risk       string `json:"risk"`
	CheckFirst string `json:"check_first"`
	Script     string `json:"script"`
}

// ActionReport is what happened for one action.
type ActionReport struct {
	Type          string        `json:"type"`
	Summary       string        `json:"summary"`
	Reversibility Reversibility `json:"reversibility"`
	UndoWhy       string        `json:"undo_why"`

	OK bool `json:"ok"`

	// Refused says, in plain words, why this action did not happen. Empty when
	// it did.
	Refused string `json:"refused,omitempty"`

	Commands []CommandRun `json:"commands"`

	// WouldRun is every command that would change this machine, written out as it
	// would be typed. Set by a dry run only; a real run reports what it did.
	//
	// It exists because a dry run runs its own steps — `cat` the file that would be
	// installed, ask the service what it believes — and those were the only commands
	// the report carried. The `install` that does the work appeared nowhere, so the
	// screen showed `cat …apt.update_package_lists=1.conf` and somebody approving
	// reasonably read that as the change. Reported from the UI.
	WouldRun []string `json:"would_run,omitempty"`

	// FreedBytes is what the dry run said would be freed, where the action frees
	// space. Zero for everything else.
	FreedBytes int64 `json:"freed_bytes,omitempty"`

	// DoItYourself is set when this action was refused because it is too dangerous
	// for us to carry out, and carries the way to do it by hand. Absent for every
	// other kind of refusal: explaining how to weaken a server is not help.
	DoItYourself *DoItYourself `json:"do_it_yourself,omitempty"`
}

// BackupReport is the honest story of the backup.
type BackupReport struct {
	Asked bool  `json:"asked"`
	Taken bool  `json:"taken"`
	Needs int64 `json:"needs_bytes,omitempty"`
	Free  int64 `json:"free_bytes,omitempty"`

	// Why says in plain words what happened and, when a backup was skipped, the
	// numbers that decided it. Never skipped quietly.
	Why string `json:"why"`
}

// LedgerEntry is one line of "what can and cannot be put back".
type LedgerEntry struct {
	Type string `json:"type"`

	// CanPutBack is whether an undo is possible at all.
	CanPutBack bool `json:"can_put_back"`

	// PutBack is whether it actually was put back. Only ever true after a real
	// undo ran.
	PutBack bool `json:"put_back"`

	Why string `json:"why"`
}

// UndoReport is the ledger, and whether an undo ran.
type UndoReport struct {
	Ran      bool          `json:"ran"`
	Ledger   []LedgerEntry `json:"ledger"`
	Commands []CommandRun  `json:"commands,omitempty"`
}

// PhaseReport is the check that the fix worked.
type PhaseReport struct {
	OK       bool         `json:"ok"`
	Commands []CommandRun `json:"commands"`
}

// Report is everything the service is told.
type Report struct {
	Mode string `json:"mode"`

	OK bool `json:"ok"`

	// Refused says why nothing ran at all — the local switch, an empty job.
	Refused string `json:"refused,omitempty"`

	// PreviewID identifies this exact preview, on a dry run only. An approval
	// names it, so an approval given for an older preview is detectably old.
	PreviewID string `json:"preview_id,omitempty"`

	Actions []ActionReport `json:"actions"`
	Backup  BackupReport   `json:"backup"`
	Verify  *PhaseReport   `json:"verify,omitempty"`
	Undo    *UndoReport    `json:"undo,omitempty"`
}
