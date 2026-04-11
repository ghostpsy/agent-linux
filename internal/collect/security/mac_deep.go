//go:build linux

package security

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	macDeepPsZMaxLines        = 400
	macDeepSemanageMaxLines   = 24
	macDeepCmdTimeout         = 4 * time.Second
	macDeepAaStatusTimeout    = 3 * time.Second
)

func collectMacDeep(ctx context.Context, mac *payload.SelinuxApparmorBlock) *payload.MacDeepPosture {
	out := &payload.MacDeepPosture{}
	if ctx.Err() != nil {
		out.Error = ctx.Err().Error()
		return out
	}
	if mac != nil && strings.EqualFold(mac.SelinuxMode, "enforcing") {
		sampleCap := macDeepPsZMaxLines
		out.SelinuxPsZLineSampleCap = &sampleCap
		n := countUnconfinedLikeFromPsZ(ctx, macDeepPsZMaxLines)
		out.SelinuxPsZUnconfinedLikeCount = &n
		lines, reason := semanagePermissiveSample(ctx, macDeepSemanageMaxLines)
		out.SelinuxSemanagePermissiveSample = lines
		out.SelinuxSemanageUnavailable = reason
	}
	enf, comp, aaReason := apparmorProfileCounts(ctx)
	out.ApparmorProfilesEnforceCount = enf
	out.ApparmorProfilesComplainCount = comp
	out.ApparmorStatusUnavailable = aaReason
	if macDeepIsEmpty(out) {
		return nil
	}
	return out
}

func macDeepIsEmpty(m *payload.MacDeepPosture) bool {
	if m == nil {
		return true
	}
	if m.SelinuxPsZLineSampleCap != nil || m.SelinuxPsZUnconfinedLikeCount != nil {
		return false
	}
	if len(m.SelinuxSemanagePermissiveSample) > 0 || m.SelinuxSemanageUnavailable != "" {
		return false
	}
	if m.ApparmorProfilesEnforceCount != nil || m.ApparmorProfilesComplainCount != nil {
		return false
	}
	if m.ApparmorStatusUnavailable != "" || m.Error != "" {
		return false
	}
	return true
}

func countUnconfinedLikeFromPsZ(parent context.Context, maxLines int) int {
	ctx, cancel := context.WithTimeout(parent, macDeepCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ps", "-eZ")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return 0
	}
	sc := bufio.NewScanner(&buf)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	n := 0
	lines := 0
	for sc.Scan() {
		if lines >= maxLines {
			break
		}
		lines++
		line := sc.Text()
		label := firstPsZLabelField(line)
		if selinuxLabelUnconfinedLike(label) {
			n++
		}
	}
	return n
}

func firstPsZLabelField(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return fields[0]
	}
	// Context is colon-separated; first field is full label (no spaces in MLS range in ps output).
	if strings.Contains(fields[0], ":") {
		return fields[0]
	}
	return fields[0]
}

func selinuxLabelUnconfinedLike(label string) bool {
	if label == "" || label == "-" || label == "?" {
		return true
	}
	if strings.Contains(label, "kernel_t") || strings.Contains(label, "kernel_") {
		return false
	}
	return strings.Contains(label, "unconfined_t") || strings.Contains(label, "unlabeled_t")
}

func semanagePermissiveSample(parent context.Context, maxLines int) ([]string, string) {
	if _, err := exec.LookPath("semanage"); err != nil {
		return nil, ""
	}
	ctx, cancel := context.WithTimeout(parent, macDeepCmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "semanage", "permissive", "-l")
	out, err := cmd.Output()
	if err != nil {
		return nil, "unavailable"
	}
	var lines []string
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() && len(lines) < maxLines {
		t := strings.TrimSpace(s.Text())
		if t != "" {
			lines = append(lines, shared.TruncateRunes(t, 256))
		}
	}
	return lines, ""
}

func apparmorProfileCounts(parent context.Context) (enforce *int, complain *int, unavailable string) {
	if _, err := exec.LookPath("aa-status"); err != nil {
		return nil, nil, ""
	}
	ctx, cancel := context.WithTimeout(parent, macDeepAaStatusTimeout)
	defer cancel()
	if n, ok := aaStatusSingleInt(ctx, "--enforced"); ok {
		enforce = intPtr(n)
	}
	ctx2, cancel2 := context.WithTimeout(parent, macDeepAaStatusTimeout)
	defer cancel2()
	if n, ok := aaStatusSingleInt(ctx2, "--complaining"); ok {
		complain = intPtr(n)
	}
	if enforce != nil && complain != nil {
		return enforce, complain, ""
	}
	ctx3, cancel3 := context.WithTimeout(parent, macDeepCmdTimeout)
	defer cancel3()
	enf2, comp2, err := aaStatusCountsFromJSON(ctx3)
	if err != nil {
		if enforce == nil && complain == nil {
			return nil, nil, "unavailable"
		}
		return enforce, complain, partialAaUnavailableReason(enforce, complain)
	}
	if enforce == nil {
		enforce = intPtr(enf2)
	}
	if complain == nil {
		complain = intPtr(comp2)
	}
	return enforce, complain, ""
}

func partialAaUnavailableReason(enforce, complain *int) string {
	if enforce != nil || complain != nil {
		return ""
	}
	return "unavailable"
}

func aaStatusSingleInt(ctx context.Context, flag string) (int, bool) {
	cmd := exec.CommandContext(ctx, "aa-status", flag)
	b, err := cmd.Output()
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, false
	}
	return n, true
}

func aaStatusCountsFromJSON(ctx context.Context) (enforce int, complain int, err error) {
	cmd := exec.CommandContext(ctx, "aa-status", "--json")
	b, err := cmd.Output()
	if err != nil {
		return 0, 0, err
	}
	return parseAaStatusJSONCounts(b)
}

func parseAaStatusJSONCounts(raw []byte) (enforce int, complain int, err error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return 0, 0, err
	}
	if v, ok := top["profiles"]; ok {
		var pm map[string]json.RawMessage
		if json.Unmarshal(v, &pm) == nil {
			enforce = firstIntInMap(pm, "enforce", "enforced", "profiles_enforce")
			complain = firstIntInMap(pm, "complain", "complaining", "profiles_complain")
			if enforce > 0 || complain > 0 {
				return enforce, complain, nil
			}
		}
		var n int
		if json.Unmarshal(v, &n) == nil && n > 0 {
			return n, 0, nil
		}
	}
	enforce = firstIntInMap(top, "profiles_enforce", "enforce", "enforced", "profiles_in_enforce")
	complain = firstIntInMap(top, "profiles_complain", "complain", "complaining", "profiles_in_complain")
	if enforce == 0 && complain == 0 {
		return 0, 0, errors.New("no apparmor profile counts in json")
	}
	return enforce, complain, nil
}

func firstIntInMap(m map[string]json.RawMessage, keys ...string) int {
	for _, k := range keys {
		if raw, ok := m[k]; ok {
			var n int
			if json.Unmarshal(raw, &n) == nil {
				return n
			}
		}
	}
	return 0
}

func intPtr(n int) *int {
	return &n
}
