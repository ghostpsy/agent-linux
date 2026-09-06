//go:build linux

package identity

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/payload"
	"github.com/ghostpsy/agent-linux/internal/privexec"
)

// sudoersAudit reads /etc/sudoers and its directory when it can, and asks grep
// when it cannot.
//
// It used to run `ghostpsy read-sudoers`. That printed the counts and nothing
// else, which was tidy, but the sudo rule named our own binary and a security
// team could not tell what it did without reading our source.
//
// The grant is now `grep -rn . /etc/sudoers /etc/sudoers.d/` — print these
// files, numbered. The rule text does reach this process, where it did not
// before. It goes no further: what leaves here is still the counts.
func sudoersAudit(ctx context.Context) *payload.SudoersAudit {
	if os.Geteuid() == 0 {
		return collectSudoersAuditLocal()
	}

	res, err := privexec.Run(ctx, privexec.SudoersText)
	if err != nil {
		return &payload.SudoersAudit{Error: "sudoers could not be read"}
	}
	return parseGrepSudoers(res.Stdout)
}

// grepFields is how many parts a `grep -rn` line has: path, line number, text.
// Three, never more — a sudo rule is full of colons and must be kept whole.
const grepFields = 3

// mainSudoersPath is the file whose Defaults lines apply to the whole host. The
// audit treats it differently from a drop-in, so it has to be recognised.
const mainSudoersPath = "/etc/sudoers"

// parseGrepSudoers turns `grep -rn` output back into per-file content and audits
// each file the way the root path audits it.
//
// Files keep the order grep printed them in, which is the order they appear on
// disk. The audit reports which files it saw, and a set would lose that.
func parseGrepSudoers(raw []byte) *payload.SudoersAudit {
	order, byFile := groupGrepLinesByFile(raw)
	if len(order) == 0 {
		return &payload.SudoersAudit{Error: "sudoers could not be read"}
	}

	out := &payload.SudoersAudit{}
	for _, path := range order {
		out.FilesScanned = append(out.FilesScanned, path)
		scanSudoersContent(strings.Join(byFile[path], "\n"), out, path == mainSudoersPath)
	}
	return out
}

// groupGrepLinesByFile collects each file's lines, and remembers the order the
// files first appeared in.
func groupGrepLinesByFile(raw []byte) ([]string, map[string][]string) {
	var order []string
	byFile := map[string][]string{}

	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.SplitN(line, ":", grepFields)
		if len(parts) != grepFields {
			continue
		}
		path := parts[0]
		if _, seen := byFile[path]; !seen {
			order = append(order, path)
		}
		byFile[path] = append(byFile[path], parts[2])
	}
	return order, byFile
}

// SudoersAuditJSON renders the audit from the files themselves. Only root can do
// this, and only the scan running as root ever calls it.
func SudoersAuditJSON() ([]byte, error) {
	return json.Marshal(collectSudoersAuditLocal())
}
