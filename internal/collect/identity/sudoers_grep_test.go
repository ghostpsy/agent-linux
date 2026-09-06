//go:build linux

package identity

import "testing"

// `grep -rn . /etc/sudoers /etc/sudoers.d/` prints path:line:text. Regrouping it
// per file has to give the same audit the file reader gives, or swapping to a
// standard command has cost us the finding.
const grepSudoersSample = `/etc/sudoers:1:Defaults	env_reset
/etc/sudoers:2:root	ALL=(ALL:ALL) ALL
/etc/sudoers:3:%admin ALL=(ALL) NOPASSWD: ALL
/etc/sudoers.d/README:1:# This is a README
/etc/sudoers.d/ghostpsy:1:ghostpsy ALL=(root) NOPASSWD: /bin/cat /etc/sudoers.d/ghostpsy
`

func TestGrepSudoersListsEveryFileItSaw(t *testing.T) {
	got := parseGrepSudoers([]byte(grepSudoersSample))

	want := []string{"/etc/sudoers", "/etc/sudoers.d/README", "/etc/sudoers.d/ghostpsy"}
	if len(got.FilesScanned) != len(want) {
		t.Fatalf("files scanned: got %v, want %v", got.FilesScanned, want)
	}
	for i, path := range want {
		if got.FilesScanned[i] != path {
			t.Errorf("file %d: got %q, want %q", i, got.FilesScanned[i], path)
		}
	}
}

func TestGrepSudoersCountsTheRisksAcrossEveryFile(t *testing.T) {
	got := parseGrepSudoers([]byte(grepSudoersSample))

	if got.NopasswdMentionCount != 2 {
		t.Errorf("NOPASSWD mentions: got %d, want 2", got.NopasswdMentionCount)
	}
	if got.AllAllPatternCount < 1 {
		t.Errorf("ALL=(ALL) rules: got %d, want at least 1", got.AllAllPatternCount)
	}
}

// A rule body may contain a colon — the ghostpsy grant is full of them. Splitting
// on every colon would cut the rule in half and lose whatever came after.
func TestGrepSudoersKeepsColonsInsideARule(t *testing.T) {
	got := parseGrepSudoers([]byte("/etc/sudoers.d/x:1:bob ALL=(ALL:ALL) NOPASSWD: /bin/ls\n"))

	if got.NopasswdMentionCount != 1 {
		t.Errorf("a rule with colons in it was not read whole: %+v", got)
	}
}

// grep says so on stderr and prints nothing. An empty answer is not "no rules".
func TestGrepSudoersReportsWhenItReadNothing(t *testing.T) {
	got := parseGrepSudoers(nil)

	if got.Error == "" {
		t.Error("reading no sudoers file at all has to be an error, not an empty audit")
	}
}
