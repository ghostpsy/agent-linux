//go:build linux

package filesystem

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/collect/shared"
	"github.com/ghostpsy/agent-linux/internal/payload"
)

const maxCrypttabNames = 8
const maxLsblkCryptNames = 16

// CollectCryptStorageHint summarizes crypttab and lsblk crypt volumes (no key material).
func CollectCryptStorageHint() *payload.CryptStorageHint {
	out := &payload.CryptStorageHint{}
	b, err := os.ReadFile("/etc/crypttab")
	if err != nil {
		if !os.IsNotExist(err) {
			out.Error = "crypttab not readable"
		}
	} else {
		out.CrypttabReadable = true
		names, n := parseCrypttabMapperNames(string(b))
		out.CrypttabEntryCount = n
		out.CrypttabMapperNamesSample = names
	}
	fillLsblkCrypt(out)
	return out
}

func parseCrypttabMapperNames(content string) (sample []string, count int) {
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		name := fields[0]
		count++
		if len(sample) < maxCrypttabNames {
			sample = append(sample, shared.TruncateRunes(name, 128))
		}
	}
	return sample, count
}

func fillLsblkCrypt(out *payload.CryptStorageHint) {
	cmd := exec.Command("lsblk", "-J", "-o", "NAME,TYPE")
	b, err := cmd.Output()
	if err != nil {
		return
	}
	var root lsblkJSON
	if err := json.Unmarshal(b, &root); err != nil {
		return
	}
	var names []string
	walkLsblkBlocks(root.Blockdevices, &names)
	out.LsblkCryptVolumeCount = len(names)
	if len(names) > maxLsblkCryptNames {
		names = names[:maxLsblkCryptNames]
	}
	out.LsblkCryptNamesSample = names
}

type lsblkJSON struct {
	Blockdevices []lsblkNode `json:"blockdevices"`
}

type lsblkNode struct {
	Name     string      `json:"name"`
	Type     string      `json:"type"`
	Children []lsblkNode `json:"children"`
}

func walkLsblkBlocks(nodes []lsblkNode, names *[]string) {
	for _, n := range nodes {
		if strings.EqualFold(n.Type, "crypt") && n.Name != "" {
			*names = append(*names, n.Name)
		}
		if len(n.Children) > 0 {
			walkLsblkBlocks(n.Children, names)
		}
	}
}
