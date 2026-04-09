//go:build linux

package logging

import "github.com/ghostpsy/agent-linux/internal/payload"

// CollectLoggingAndSystemAuditing gathers §7 logging, auditd, logrotate/disk, at/batch, and process-accounting hints.
func CollectLoggingAndSystemAuditing() payload.LoggingAndSystemAuditingComponent {
	out := payload.LoggingAndSystemAuditingComponent{}
	if s := collectSyslogForwarding(); syslogForwardingNonEmpty(s) {
		out.SyslogForwarding = s
	}
	if j := collectJournaldPosture(); journaldNonEmpty(j) {
		out.Journald = j
	}
	if a := collectAuditdPosture(); auditdNonEmpty(a) {
		out.Auditd = a
	}
	if l := collectLogrotateDiskPosture(); logrotateNonEmpty(l) {
		out.LogrotateDisk = l
	}
	if t := collectAtBatchPosture(); atBatchNonEmpty(t) {
		out.AtBatch = t
	}
	if p := collectProcessAccountingPosture(); processAccountingNonEmpty(p) {
		out.ProcessAccounting = p
	}
	return out
}

func syslogForwardingNonEmpty(s *payload.SyslogForwardingPosture) bool {
	return s != nil && (len(s.Daemons) > 0 || s.Error != "")
}

func journaldNonEmpty(j *payload.JournaldPosture) bool {
	if j == nil {
		return false
	}
	if j.Error != "" {
		return true
	}
	if j.UnitActive != "" {
		return true
	}
	if len(j.ConfigPathsRead) > 0 {
		return true
	}
	if j.Storage != "" || j.JournalctlDiskUsageSummary != "" {
		return true
	}
	if j.SystemMaxUse != "" || j.RuntimeMaxUse != "" || j.MaxRetentionSec != "" {
		return true
	}
	if j.ForwardToSyslog != nil || j.ForwardToWall != nil || j.ForwardToConsole != nil {
		return true
	}
	if j.Compress != nil || j.Seal != nil {
		return true
	}
	return false
}

func auditdNonEmpty(a *payload.AuditdPosture) bool {
	if a == nil {
		return false
	}
	return a.UnitActive != "" || a.RuleLineCount != nil || len(a.RulesDropInFiles) > 0 || a.AuditctlUnavailableReason != "" || a.Error != ""
}

func logrotateNonEmpty(l *payload.LogrotateDiskPosture) bool {
	if l == nil {
		return false
	}
	return l.MainConfPresent || l.VarLogStanzaHint || l.VarLogMountUsedPct != nil || l.Error != ""
}

func atBatchNonEmpty(t *payload.AtBatchPosture) bool {
	if t == nil {
		return false
	}
	return t.AtdUnitActive != "" || t.AtAllowPresent || t.AtDenyPresent || t.SpoolPathUsed != "" || t.Error != ""
}

func processAccountingNonEmpty(p *payload.ProcessAccountingPosture) bool {
	if p == nil {
		return false
	}
	return p.SadcOnPath || p.SysstatCronHint || p.LdSoPreloadFilePresent || p.Error != ""
}
