//go:build linux

package identity

import (
	"context"
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

const (
	passwdPath        = "/etc/passwd"
	groupPath         = "/etc/group"
	maxDuplicateNames = 4
)

// CollectDuplicateUidGid reports passwd/group IDs shared by more than one account (names capped).
func CollectDuplicateUidGid(ctx context.Context) *payload.DuplicateUidGid {
	out := &payload.DuplicateUidGid{}
	uidMap := map[int][]string{}
	if err := scanPasswdUids(uidMap); err != nil {
		out.Error = "passwd could not be read completely"
		return out
	}
	gidMap := map[int][]string{}
	if err := scanGroupGids(gidMap); err != nil {
		out.Error = "group could not be read completely"
		return out
	}
	out.DuplicateUids = entriesFromMap(uidMap)
	out.DuplicateGids = entriesFromMap(gidMap)
	out.DuplicateUidCount = len(out.DuplicateUids)
	out.DuplicateGidCount = len(out.DuplicateGids)
	return out
}

func scanPasswdUids(uidMap map[int][]string) error {
	f, err := os.Open(passwdPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		name := parts[0]
		uid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		uidMap[uid] = append(uidMap[uid], name)
	}
	return sc.Err()
}

func scanGroupGids(gidMap map[int][]string) error {
	f, err := os.Open(groupPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		name := parts[0]
		gid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		gidMap[gid] = append(gidMap[gid], name)
	}
	return sc.Err()
}

func entriesFromMap(m map[int][]string) []payload.DuplicateIDEntry {
	var ids []int
	for id, names := range m {
		if len(names) > 1 {
			ids = append(ids, id)
		}
	}
	sort.Ints(ids)
	out := make([]payload.DuplicateIDEntry, 0, len(ids))
	for _, id := range ids {
		names := uniqueSortedNames(m[id])
		if len(names) > maxDuplicateNames {
			names = names[:maxDuplicateNames]
		}
		out = append(out, payload.DuplicateIDEntry{ID: id, Names: names})
	}
	return out
}

func uniqueSortedNames(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	for _, n := range names {
		if n == "" {
			continue
		}
		seen[n] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
