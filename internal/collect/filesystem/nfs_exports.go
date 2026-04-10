//go:build linux

package filesystem

import (
	"context"
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

var nfsClientSpec = regexp.MustCompile(`[a-zA-Z0-9._:/\-]+\(([^)]*)\)`)

// CollectNfsExportsFingerprint parses /etc/exports with path hashes (no raw paths).
func CollectNfsExportsFingerprint(ctx context.Context) *payload.NfsExportsFingerprint {
	out := &payload.NfsExportsFingerprint{}
	f, err := os.Open("/etc/exports")
	if err != nil {
		if os.IsNotExist(err) {
			return out
		}
		out.Error = "exports not readable"
		return out
	}
	defer func() { _ = f.Close() }()
	out.ExportsReadable = true
	sc := bufio.NewScanner(f)
	idx := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		exportPath := fields[0]
		if !strings.HasPrefix(exportPath, "/") {
			continue
		}
		idx++
		ent := payload.NfsExportEntry{Index: idx, PathHash: hashPath(exportPath)}
		optsBlob := strings.ToLower(strings.Join(fields[1:], " "))
		ent.CombinedOptionsFingerprint = fingerprintOpts(optsBlob)
		ent.HasNoRootSquash = strings.Contains(optsBlob, "no_root_squash")
		ent.HasRootSquash = strings.Contains(optsBlob, "root_squash") || strings.Contains(optsBlob, "all_squash")
		ent.SecModeHint = extractSecMode(optsBlob)
		all := strings.Join(fields[1:], " ")
		for _, m := range nfsClientSpec.FindAllStringSubmatch(all, -1) {
			if len(m) < 2 {
				continue
			}
			inner := strings.ToLower(m[1])
			if strings.Contains(inner, "no_root_squash") {
				ent.HasNoRootSquash = true
			}
			if strings.Contains(inner, "root_squash") || strings.Contains(inner, "all_squash") {
				ent.HasRootSquash = true
			}
			if sm := extractSecMode(inner); sm != "" {
				ent.SecModeHint = sm
			}
		}
		out.Entries = append(out.Entries, ent)
	}
	return out
}

func hashPath(p string) string {
	h := sha256.Sum256([]byte(p))
	return hex.EncodeToString(h[:8])
}

func fingerprintOpts(s string) string {
	var parts []string
	for _, tok := range []string{"rw", "ro", "sync", "async", "no_root_squash", "root_squash", "all_squash"} {
		if strings.Contains(s, tok) {
			parts = append(parts, tok)
		}
	}
	if len(parts) == 0 {
		return "present"
	}
	return strings.Join(parts, ",")
}

func extractSecMode(s string) string {
	i := strings.Index(s, "sec=")
	if i < 0 {
		return ""
	}
	rest := s[i+4:]
	end := strings.IndexAny(rest, ",)\t ")
	if end >= 0 {
		rest = rest[:end]
	}
	return strings.TrimSpace(rest)
}
