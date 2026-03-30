//go:build linux

package collect

import "ghostpsy/agent-linux/internal/payload"

// Stub builds a v1 payload (collectors fill listeners / iptables; other blocks optional).
func Stub(machineUUID string, scanSeq int) payload.V1 {
	hn, hnErr := CollectHostNetwork()
	iptLines, iptErr := CollectIptables()
	hd, hdErr := CollectHostDisk()
	hus, husErr := CollectHostUsersSummary()
	pu, puErr := CollectPackagesUpdates()
	svItems, svErr := CollectServices()

	if svItems == nil {
		svItems = []payload.ServiceEntry{}
	}

	iptBlock := payload.IptablesBlock{Items: iptLines}
	if iptErr != "" {
		iptBlock.Error = iptErr
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
	return payload.V1{
		SchemaVersion:    1,
		MachineUUID:      machineUUID,
		ScanSeq:          scanSeq,
		OS:               osInfo,
		Listeners:        CollectListeners(hn),
		Iptables:         iptBlock,
		HostDisk:         hd,
		HostNetwork:      hn,
		HostUsersSummary: hus,
		PackagesUpdates:  pu,
		HostTime:         CollectHostTime(),
		Firewall:         CollectFirewall(),
		Services:         servicesBlock,
	}
}
