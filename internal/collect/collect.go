//go:build linux

package collect

import (
	"ghostpsy/agent-linux/internal/collect/firewall"
	"ghostpsy/agent-linux/internal/payload"
)

// Stub builds a v1 payload (listeners include firewall_rule; other blocks optional).
func Stub(machineUUID string, scanSeq int) payload.V1 {
	hn, hnErr := CollectHostNetwork()
	hd, hdErr := CollectHostDisk()
	hus, husErr := CollectHostUsersSummary()
	pu, puErr := CollectPackagesUpdates()
	hb := CollectHostBackup()
	svItems, svErr := CollectServices()

	if svItems == nil {
		svItems = []payload.ServiceEntry{}
	}

	servicesBlock := payload.ServicesBlock{Items: svItems}
	if svErr != "" {
		servicesBlock.Error = svErr
	}

	if hd == nil && hdErr != "" {
		hd = &payload.HostDisk{}
		hd.Error = hdErr
	}
	if hn == nil && hnErr != "" {
		hn = &payload.HostNetwork{}
		hn.Error = hnErr
	}
	if hus == nil && husErr != "" {
		hus = &payload.HostUsersSummary{}
		hus.Error = husErr
	}
	if pu == nil && puErr != "" {
		pu = &payload.PackagesUpdates{}
		pu.Error = puErr
	}

	osInfo := CollectOSInfo()
	fw := firewall.CollectFirewall()
	listeners := firewall.ApplyFirewallRuleToListeners(CollectListeners(hn), fw)
	return payload.V1{
		SchemaVersion:    1,
		MachineUUID:      machineUUID,
		ScanSeq:          scanSeq,
		OS:               osInfo,
		Listeners:        listeners,
		HostDisk:         hd,
		HostNetwork:      hn,
		HostUsersSummary: hus,
		PackagesUpdates:  pu,
		HostBackup:       hb,
		HostTime:         CollectHostTime(),
		Firewall:         fw,
		Services:         servicesBlock,
	}
}
