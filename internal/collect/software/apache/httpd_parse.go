//go:build linux

package apache

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	apacheMaxServerNames    = 48
	apacheMaxListenBindings = 64
)

var (
	reApacheNamevhost = regexp.MustCompile(`(?i)^\s+port\s+(\d+)\s+namevhost\s+(\S+)\s+\(`)
	reApacheDefault   = regexp.MustCompile(`(?i)\bdefault server\s+(\S+)\s+\(`)
	reApacheBindNVH   = regexp.MustCompile(`^([^:]+):(\d+)\s+is a NameVirtualHost\s*$`)
	reApacheAddrVhost = regexp.MustCompile(`^(\*|[0-9a-fA-F:.]+|\[[0-9a-fA-F:%.]+\]):(\d+)\s+(\S+)\s+\(`)
)

type apacheParsedDump struct {
	vhostCount  int
	serverNames []string
	listenBinds []apacheListenKey
}

type apacheListenKey struct {
	bind string
	port int
}

// parseApacheVersionLine extracts the Server version line from `httpd -v` / `apache2 -v` output.
func parseApacheVersionLine(vOut string) string {
	for _, line := range strings.Split(vOut, "\n") {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "server version:") {
			rest := strings.TrimSpace(line[len("Server version:"):])
			if rest != "" {
				return rest
			}
		}
	}
	first := strings.TrimSpace(vOut)
	if idx := strings.IndexByte(first, '\n'); idx >= 0 {
		first = strings.TrimSpace(first[:idx])
	}
	return first
}

// parseApacheSDump parses bounded `apache2 -S` / `httpd -S` output (VirtualHost configuration).
func parseApacheSDump(sOut string) apacheParsedDump {
	lines := strings.Split(sOut, "\n")
	nameSet := make(map[string]struct{})
	var binds []apacheListenKey
	bindSet := make(map[apacheListenKey]struct{})
	vhostLines := 0

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if m := reApacheBindNVH.FindStringSubmatch(line); len(m) == 3 {
			port, err := strconv.Atoi(m[2])
			if err != nil {
				continue
			}
			k := apacheListenKey{bind: m[1], port: port}
			if _, ok := bindSet[k]; !ok && len(binds) < apacheMaxListenBindings {
				bindSet[k] = struct{}{}
				binds = append(binds, k)
			}
			continue
		}
		if m := reApacheNamevhost.FindStringSubmatch(line); len(m) == 3 {
			vhostLines++
			name := strings.TrimSpace(m[2])
			if name != "" && len(nameSet) < apacheMaxServerNames {
				nameSet[name] = struct{}{}
			}
			continue
		}
		if m := reApacheDefault.FindStringSubmatch(line); len(m) == 2 {
			name := strings.TrimSpace(m[1])
			if name != "" && len(nameSet) < apacheMaxServerNames {
				nameSet[name] = struct{}{}
			}
			continue
		}
		if m := reApacheAddrVhost.FindStringSubmatch(line); len(m) == 4 {
			vhostLines++
			port, err := strconv.Atoi(m[2])
			if err != nil {
				continue
			}
			k := apacheListenKey{bind: m[1], port: port}
			if _, ok := bindSet[k]; !ok && len(binds) < apacheMaxListenBindings {
				bindSet[k] = struct{}{}
				binds = append(binds, k)
			}
			name := strings.TrimSpace(m[3])
			if name != "" && !strings.EqualFold(name, "is") && len(nameSet) < apacheMaxServerNames {
				nameSet[name] = struct{}{}
			}
		}
	}

	names := make([]string, 0, len(nameSet))
	for n := range nameSet {
		names = append(names, n)
	}
	sort.Strings(names)

	sort.Slice(binds, func(i, j int) bool {
		if binds[i].bind != binds[j].bind {
			return binds[i].bind < binds[j].bind
		}
		return binds[i].port < binds[j].port
	})

	count := vhostLines
	if count == 0 && len(nameSet) > 0 {
		count = len(nameSet)
	}

	return apacheParsedDump{
		vhostCount:  count,
		serverNames: names,
		listenBinds: binds,
	}
}
