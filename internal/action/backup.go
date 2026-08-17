//go:build linux

package action

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The backup is an option, not a promise, and the condition is measured at the
// moment of running.
//
// The first fix we ship proves why. Freeing a full disk means deleting several
// gigabytes of logs. Archiving them first needs those same gigabytes on the very
// disk we are emptying, so the backup would cause the exact problem the fix
// exists to solve. The old rule — never act without a backup — would either block
// the fix or fill the disk.
//
// So: measure the space, decide out loud, and never skip quietly.

// previewBackup says what the backup would be, without writing anything.
func previewBackup(deps Deps, plans []plan, reports []ActionReport, asked bool) BackupReport {
	out := BackupReport{Asked: asked}

	needs, target := backupNeeds(plans, reports)
	if needs == 0 {
		out.Why = "nothing here needs a copy taken first"
		return out
	}
	out.Needs = needs

	free, err := deps.FreeBytes(target)
	if err != nil {
		out.Why = fmt.Sprintf("ghostpsy could not measure the free space on %s, so it will not "+
			"write a backup it cannot be sure fits", target)
		return out
	}
	out.Free = free

	if !fits(needs, free) {
		out.Why = wouldNotFit(needs, free, target)
		return out
	}
	out.Why = fmt.Sprintf("a backup of about %s will be written before anything changes",
		humanBytes(needs))
	return out
}

// decideBackup measures the machine as it is now and takes the copy, or refuses
// to and says why in plain words.
func decideBackup(ctx context.Context, deps Deps, plans []plan, asked bool, report *Report) BackupReport {
	out := BackupReport{Asked: asked}
	if !asked {
		out.Why = "no backup was asked for"
		return out
	}

	// The size can only come from a preview, and the preview has to be of this
	// machine right now. An old number would be exactly the assumption this
	// whole design refuses to make.
	needs, target := measureNow(ctx, deps, plans, report)
	if needs == 0 {
		out.Why = "nothing here needs a copy taken first"
		return out
	}
	out.Needs = needs

	free, err := deps.FreeBytes(target)
	if err != nil {
		out.Why = fmt.Sprintf("ghostpsy could not measure the free space on %s, so it did not "+
			"write a backup it could not be sure fits. Nothing was undone by this — the fix still "+
			"ran, and the changes it makes cannot be put back", target)
		return out
	}
	out.Free = free

	if !fits(needs, free) {
		out.Why = wouldNotFit(needs, free, target)
		return out
	}

	taken, why := takeCopies(plans)
	out.Taken = taken
	out.Why = why
	return out
}

// measureNow runs the dry run of any action whose backup size can only be known
// from it, and returns the bytes needed and the filesystem they would go on.
//
// A dry run changes nothing, which is what makes it safe to do here.
func measureNow(ctx context.Context, deps Deps, plans []plan, report *Report) (int64, string) {
	for i := range plans {
		if plans[i].variant.Backup.Kind != BackupArchiveFreed {
			continue
		}
		if report.Actions[i].FreedBytes > 0 {
			continue
		}
		runs, _ := runPhase(ctx, deps, plans[i], plans[i].variant.DryRun)
		report.Actions[i].Commands = append(report.Actions[i].Commands, runs...)
		report.Actions[i].FreedBytes = freedFrom(plans[i], runs)
	}
	return backupNeeds(plans, report.Actions)
}

// backupNeeds adds up what a backup of this whole job would take, and says which
// filesystem it would land on.
func backupNeeds(plans []plan, reports []ActionReport) (int64, string) {
	var needs int64
	target := "/"

	for i := range plans {
		switch plans[i].variant.Backup.Kind {
		case BackupCopyFiles:
			// A config file is kilobytes. The copy goes next to the original,
			// and the space it needs is never the deciding factor.
			needs += smallCopyBytes
			target = plans[i].variant.Backup.Target
		case BackupArchiveFreed:
			needs += reports[i].FreedBytes
			target = plans[i].variant.Backup.Target
		case BackupNone:
		}
	}
	return needs, target
}

// smallCopyBytes is what we reserve for copying a config file aside. Generous on
// purpose: being wrong in this direction costs a few kilobytes.
const smallCopyBytes = 1 << 20

// backupHeadroom is the space a backup must leave behind it.
//
// Filling a disk to the last byte breaks things that have nothing to do with the
// fix — a database cannot write, a log cannot rotate, and sometimes the machine
// cannot boot. A backup that only just fits does not fit.
const backupHeadroom = 512 << 20

func fits(needs, free int64) bool {
	return free-needs >= backupHeadroom
}

func wouldNotFit(needs, free int64, target string) string {
	return fmt.Sprintf(
		"No backup was taken, and it could not be. A backup would need about %s, and only %s is "+
			"free on %s. Writing it would fill the disk you are trying to empty. ghostpsy will "+
			"not do that. This means the changes below cannot be put back.",
		humanBytes(needs), humanBytes(free), target)
}

// takeCopies reports which files will be copied aside before being edited.
//
// It runs nothing itself. The copy is taken inside the same privileged step that
// edits the file — see internal/confedit — so that a file this agent changes can
// never have been changed without one. A separate copy step would be a step that
// could be skipped.
func takeCopies(plans []plan) (bool, string) {
	var copied []string

	for i := range plans {
		if plans[i].variant.Backup.Kind == BackupCopyFiles {
			copied = append(copied, plans[i].variant.Backup.Target)
		}
	}
	if len(copied) == 0 {
		return false, "nothing here needed a copy taken first"
	}
	return true, "a copy of " + strings.Join(copied, ", ") +
		" is written before it is edited, and it is what an undo puts back"
}

// freedFrom reads how much space a dry run says would be freed.
//
// The number comes from the tool's own output rather than from an estimate of
// ours, because it is what decides whether a backup is possible at all.
func freedFrom(p plan, runs []CommandRun) int64 {
	if p.variant.Backup.Freed == nil {
		return 0
	}
	var total int64
	for _, run := range runs {
		for _, match := range p.variant.Backup.Freed.FindAllStringSubmatch(run.Stdout, -1) {
			total += parseBytes(match[1])
		}
	}
	return total
}

// sizeText matches the sizes Linux tools print: 4.2G, 128.0M, 1.9GB, 6144K.
var sizeText = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)\s*([KMGTB]?)i?B?$`)

var sizeUnit = map[string]int64{
	"":  1,
	"B": 1,
	"K": 1 << 10,
	"M": 1 << 20,
	"G": 1 << 30,
	"T": 1 << 40,
}

// parseBytes turns a size a tool printed into bytes. An unreadable size is zero,
// which makes the backup decision cautious rather than wrong.
func parseBytes(text string) int64 {
	match := sizeText.FindStringSubmatch(strings.TrimSpace(text))
	if match == nil {
		return 0
	}
	amount, err := strconv.ParseFloat(match[1], 64)
	if err != nil {
		return 0
	}
	return int64(amount * float64(sizeUnit[match[2]]))
}

// humanBytes writes a size the way the person reading the screen would.
func humanBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d bytes", b)
	}
}
