//go:build linux

package nginx

import (
	"fmt"
	"strings"

	"github.com/ghostpsy/agent-linux/internal/payload"
)

func nginxNormBind(b string) string {
	b = strings.TrimSpace(strings.ToLower(b))
	switch b {
	case "", "*", "0.0.0.0", "::", "[::]":
		return "*"
	}
	return b
}

func filterNginxListeners(listeners []payload.Listener) []payload.Listener {
	var out []payload.Listener
	for _, li := range listeners {
		p := strings.ToLower(li.Process)
		if strings.Contains(p, "nginx") || strings.Contains(p, "openresty") {
			out = append(out, li)
		}
	}
	return out
}

func compareNginxListenVsSnapshot(keys []nginxListenKey, listeners []payload.Listener) []string {
	if len(keys) == 0 {
		return []string{}
	}
	nl := filterNginxListeners(listeners)
	if len(nl) == 0 {
		var out []string
		for _, k := range keys {
			out = append(out, fmt.Sprintf("listen %s:%d has no matching nginx/openresty TCP listener in scan snapshot", k.bind, k.port))
		}
		return out
	}
	var disc []string
	for _, k := range keys {
		if !nginxListenerSnapshotHasPort(nl, k) {
			disc = append(disc, fmt.Sprintf("listen %s:%d has no matching nginx/openresty TCP listener in scan snapshot", k.bind, k.port))
		}
	}
	return disc
}

func nginxListenerSnapshotHasPort(nl []payload.Listener, want nginxListenKey) bool {
	for _, li := range nl {
		if li.Port != want.port {
			continue
		}
		lb := nginxNormBind(li.Bind)
		wb := nginxNormBind(want.bind)
		if lb == "*" || wb == "*" || lb == wb {
			return true
		}
	}
	return false
}
