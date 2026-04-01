//go:build linux

package collect

import (
	"ghostpsy/agent-linux/internal/collect/firewall"
	"ghostpsy/agent-linux/internal/payload"
)

type ActionEventObserver func(event ActionEvent)

type ActionEvent struct {
	Action string
	Phase  string
	Items  int
	Error  string
}

// Stub builds a v1 payload (listeners include firewall_rule; other blocks optional).
func Stub(machineUUID string, scanSeq int) payload.V1 {
	return StubWithObserver(machineUUID, scanSeq, nil)
}

// StubWithObserver builds a v1 payload and calls observe before each data collection action.
func StubWithObserver(machineUUID string, scanSeq int, observe ActionEventObserver) payload.V1 {
	notifyStart := func(action string) {
		if observe != nil {
			observe(ActionEvent{Action: action, Phase: "start"})
		}
	}
	notifyDone := func(action string, items int, err string) {
		if observe != nil {
			observe(ActionEvent{Action: action, Phase: "done", Items: items, Error: err})
		}
	}

	notifyStart("collect_host_network")
	hn, hnErr := CollectHostNetwork()
	notifyDone("collect_host_network", len(hostNetworkInterfaces(hn)), hnErr)
	notifyStart("collect_host_disk")
	hd, hdErr := CollectHostDisk()
	notifyDone("collect_host_disk", len(hostDiskFilesystems(hd)), hdErr)
	notifyStart("collect_host_users_summary")
	hus, husErr := CollectHostUsersSummary()
	notifyDone("collect_host_users_summary", len(hostUsersSample(hus)), husErr)
	notifyStart("collect_packages_updates")
	pu, puErr := CollectPackagesUpdates()
	notifyDone("collect_packages_updates", packagesPendingUpdatesCount(pu), puErr)
	notifyStart("collect_host_backup")
	hb := CollectHostBackup()
	notifyDone("collect_host_backup", len(hb.ToolsDetected), hostBackupLogError(hb))
	notifyStart("collect_services")
	svItems, svErr := CollectServices()
	notifyDone("collect_services", len(svItems), svErr)

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

	notifyStart("collect_os_info")
	osInfo := CollectOSInfo()
	notifyDone("collect_os_info", nonEmptyOSInfoFields(osInfo), "")
	notifyStart("collect_firewall")
	fw := firewall.CollectFirewall()
	notifyDone("collect_firewall", firewallRuleCount(fw), firewallError(fw))
	notifyStart("collect_listeners")
	listeners := firewall.ApplyFirewallRuleToListeners(CollectListeners(hn), fw)
	notifyDone("collect_listeners", len(listeners), "")
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

func hostNetworkInterfaces(hn *payload.HostNetwork) []payload.NetworkIface {
	if hn == nil {
		return nil
	}
	return hn.Interfaces
}

func hostDiskFilesystems(hd *payload.HostDisk) []payload.FilesystemEntry {
	if hd == nil {
		return nil
	}
	return hd.Filesystems
}

func hostUsersSample(hus *payload.HostUsersSummary) []payload.UserSample {
	if hus == nil {
		return nil
	}
	return hus.Sample
}

func packagesPendingUpdatesCount(pu *payload.PackagesUpdates) int {
	if pu == nil {
		return 0
	}
	return pu.PendingUpdatesCount
}

func hostBackupLogError(hb *payload.HostBackup) string {
	if hb == nil {
		return "No backup information could be extracted."
	}
	if hb.Error != "" {
		return hb.Error
	}
	if hb.BackupStatus == "on" {
		return ""
	}
	return "No backup found from paths " + backupPathsForLogs()
}

func backupPathsForLogs() string {
	return joinComma(backupDatePaths)
}

func joinComma(values []string) string {
	if len(values) == 0 {
		return ""
	}
	out := values[0]
	for _, value := range values[1:] {
		out += ", " + value
	}
	return out
}

func nonEmptyOSInfoFields(osInfo payload.OSInfo) int {
	fields := []string{
		osInfo.Pretty,
		osInfo.Kernel,
		osInfo.KernelArch,
		osInfo.DistroID,
		osInfo.DistroName,
		osInfo.DistroVersionID,
		osInfo.OSReleaseID,
		osInfo.OSReleaseVersionID,
		osInfo.OSReleaseVersion,
		osInfo.OSReleaseName,
		osInfo.Platform,
		osInfo.PlatformFamily,
		osInfo.PlatformVersion,
	}
	count := 0
	for _, field := range fields {
		if field != "" {
			count++
		}
	}
	return count
}

func firewallRuleCount(fw *payload.Firewall) int {
	if fw == nil || fw.RuleCount == nil {
		return 0
	}
	return *fw.RuleCount
}

func firewallError(fw *payload.Firewall) string {
	if fw == nil {
		return "No firewall information could be extracted."
	}
	return fw.Error
}
