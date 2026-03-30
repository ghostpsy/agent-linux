//go:build linux

package collect

import (
	"net"
	"strings"

	"ghostpsy/agent-linux/internal/payload"
)

const (
	bindScopeAllInterfaces = "all_interfaces"
	bindScopeLocalhost     = "localhost"
	bindScopeLAN           = "lan"
	bindScopeUnknown       = "unknown"
	exposureInternet       = "internet_exposed"
	exposureInternal       = "internal_only"
	exposureUnknown        = "unknown"
)

func hostNetworkHasPublicIP(hn *payload.HostNetwork) bool {
	if hn == nil {
		return false
	}
	if hn.HasPublicIPv4 != nil && *hn.HasPublicIPv4 {
		return true
	}
	if hn.HasPublicIPv6 != nil && *hn.HasPublicIPv6 {
		return true
	}
	return false
}

// classifyListenerExposure derives bind_scope and exposure_risk from the listen address and host_network hints.
func classifyListenerExposure(bind string, hn *payload.HostNetwork) (bindScope string, exposureRisk string) {
	host, _, err := net.SplitHostPort(bind)
	if err != nil {
		return bindScopeUnknown, exposureUnknown
	}
	if i := strings.Index(host, "%"); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return bindScopeUnknown, exposureUnknown
	}
	if ip.IsUnspecified() {
		if hostNetworkHasPublicIP(hn) {
			return bindScopeAllInterfaces, exposureInternet
		}
		return bindScopeAllInterfaces, exposureInternal
	}
	if ip.IsLoopback() {
		return bindScopeLocalhost, exposureInternal
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return bindScopeLAN, exposureInternal
	}
	if ip.IsGlobalUnicast() {
		return bindScopeUnknown, exposureInternet
	}
	return bindScopeUnknown, exposureUnknown
}
