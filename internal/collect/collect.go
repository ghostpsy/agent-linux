//go:build linux

package collect

import (
	"github.com/ghostpsy/agent-linux/internal/collect/core"
	"github.com/ghostpsy/agent-linux/internal/collect/crypto_time"
	"github.com/ghostpsy/agent-linux/internal/collect/filesystem"
	"github.com/ghostpsy/agent-linux/internal/collect/firewall"
	"github.com/ghostpsy/agent-linux/internal/collect/identity"
	"github.com/ghostpsy/agent-linux/internal/collect/network"
	"github.com/ghostpsy/agent-linux/internal/collect/software"
	"github.com/ghostpsy/agent-linux/internal/payload"
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
	hn, hnErr := filesystem.CollectHostNetwork()
	notifyDone("collect_host_network", len(hostNetworkInterfaces(hn)), hnErr)
	notifyStart("collect_host_disk")
	hd, hdErr := filesystem.CollectHostDisk()
	notifyDone("collect_host_disk", len(hostDiskFilesystems(hd)), hdErr)
	notifyStart("collect_host_users_summary")
	hus, husErr := identity.CollectHostUsersSummary()
	notifyDone("collect_host_users_summary", len(hostUsersSample(hus)), husErr)
	notifyStart("collect_host_ssh")
	hs, hsErr := identity.CollectHostSSH()
	notifyDone("collect_host_ssh", hostSSHListenCount(hs), hsErr)
	notifyStart("collect_packages_updates")
	pu, puErr := software.CollectPackagesUpdates()
	notifyDone("collect_packages_updates", packagesPendingUpdatesCount(pu), puErr)
	notifyStart("collect_host_backup")
	hb := software.CollectHostBackup()
	notifyDone("collect_host_backup", len(hb.ToolsDetected), hostBackupLogError(hb))
	notifyStart("collect_services")
	svItems, svErr := network.CollectServices()
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
	if hs == nil && hsErr != "" {
		hs = &payload.HostSSH{}
		hs.Error = hsErr
	}
	if pu == nil && puErr != "" {
		pu = &payload.PackagesUpdates{}
		pu.Error = puErr
	}

	notifyStart("collect_os_info")
	osInfo, hostname := core.CollectOSInfo()
	fqdn := core.CollectFqdn(hostname)
	notifyDone("collect_os_info", nonEmptyOSInfoFields(osInfo), "")
	notifyStart("collect_grub")
	grubSnap := core.CollectGrubSnapshot()
	notifyDone("collect_grub", grubNotifyCount(grubSnap), grubSnap.Error)
	notifyStart("collect_firmware_boot")
	fwBoot := core.CollectFirmwareBoot()
	notifyDone("collect_firmware_boot", firmwareNotifyCount(fwBoot), fwBoot.Error)
	notifyStart("collect_systemd_health")
	sysd := core.CollectSystemdHealth()
	notifyDone("collect_systemd_health", systemdNotifyCount(sysd), sysd.Error)
	notifyStart("collect_sysctl_live")
	sysLive := core.CollectSysctlLiveProfile()
	notifyDone("collect_sysctl_live", len(sysLive.Items), sysLive.Error)
	notifyStart("collect_sysctl_overlay")
	sysOverlay := core.CollectSysctlOverlay()
	notifyDone("collect_sysctl_overlay", len(sysOverlay.Drift), sysOverlay.Error)
	notifyStart("collect_kernel_modules")
	kmods := core.CollectKernelModules()
	notifyDone("collect_kernel_modules", len(kmods.Names), kmods.Error)
	notifyStart("collect_selinux_apparmor")
	mac := core.CollectSelinuxApparmor()
	notifyDone("collect_selinux_apparmor", selinuxNotifyCount(mac), mac.Error)
	notifyStart("collect_high_risk_process")
	hrisk := core.CollectHighRiskProcessSurface()
	notifyDone("collect_high_risk_process", len(hrisk.Items), hrisk.Error)
	notifyStart("collect_firewall")
	fw := firewall.CollectFirewall()
	notifyDone("collect_firewall", firewallRuleCount(fw), firewallError(fw))
	notifyStart("collect_host_path")
	hp := filesystem.CollectHostPath()
	notifyDone("collect_host_path", len(hp.Entries), hp.Error)
	notifyStart("collect_host_suid")
	hsuid := filesystem.CollectHostSuid()
	notifyDone("collect_host_suid", len(hsuid.Items), hsuid.Error)
	notifyStart("collect_host_process")
	hproc := core.CollectHostProcess()
	notifyDone("collect_host_process", len(hproc.Top), hproc.Error)
	notifyStart("collect_host_runtimes")
	hr := software.CollectHostRuntimes()
	notifyDone("collect_host_runtimes", len(hr.Items), hr.Error)
	notifyStart("collect_host_time")
	hostTime := crypto_time.CollectHostTime()
	notifyDone("collect_host_time", 1, "")
	notifyStart("collect_listeners")
	listeners := firewall.ApplyFirewallRuleToListeners(network.CollectListeners(hn), fw)
	if listeners == nil {
		listeners = []payload.Listener{}
	}
	notifyDone("collect_listeners", len(listeners), "")
	components := payload.Components{
		CoreSystemAndKernel: payload.CoreSystemAndKernelComponent{
			OS:              osInfo,
			HostTime:        hostTime,
			HostProcess:     hproc,
			Grub:            grubSnap,
			FirmwareBoot:    fwBoot,
			SystemdHealth:   sysd,
			SysctlLive:      sysLive,
			SysctlOverlay:   sysOverlay,
			KernelModules:   kmods,
			SelinuxApparmor: mac,
			HighRiskProcess: hrisk,
		},
		IdentityAccessAndAuthentication: payload.IdentityAccessAndAuthenticationComponent{
			HostUsersSummary: hus,
			HostSSH:          hs,
		},
		FileSystemAndStorage: payload.FileSystemAndStorageComponent{
			HostDisk: hd,
			HostPath: hp,
			HostSuid: hsuid,
		},
		NetworkAndHostFirewall: payload.NetworkAndHostFirewallComponent{
			Listeners:   listeners,
			HostNetwork: hn,
			Firewall:    fw,
			Services:    servicesBlock,
		},
		SoftwarePackagesAndApplications: payload.SoftwarePackagesAndApplicationsComponent{
			PackagesUpdates: pu,
			HostBackup:      hb,
			HostRuntimes:    hr,
		},
		ContainerAndCloudNativeLinux: payload.ContainerAndCloudNativeLinuxComponent{
			HostRuntimes: hr,
		},
		LoggingAndSystemAuditing: payload.LoggingAndSystemAuditingComponent{},
		CryptographyAndTimeSynchronization: payload.CryptographyAndTimeSynchronizationComponent{
			HostTime: hostTime,
		},
		SecurityFrameworksAndMalwareDefense: payload.SecurityFrameworksAndMalwareDefenseComponent{
			HostProcess: hproc,
		},
		Other: payload.OtherComponent{},
	}
	return payload.V1{
		SchemaVersion: 1,
		MachineUUID:   machineUUID,
		ScanSeq:       scanSeq,
		Hostname:      hostname,
		Fqdn:          fqdn,
		Components:    components,
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

func hostSSHListenCount(hs *payload.HostSSH) int {
	if hs == nil {
		return 0
	}
	return len(hs.ListenAddresses)
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
	return "No backup found."
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

func grubNotifyCount(g *payload.GrubSnapshot) int {
	if g == nil {
		return 0
	}
	if g.GrubCmdlineLinux != "" || g.GrubCfgReadablePath != "" {
		return 1
	}
	return 0
}

func firmwareNotifyCount(f *payload.FirmwareBoot) int {
	if f == nil {
		return 0
	}
	if f.BootMode != "unknown" {
		return 1
	}
	return 0
}

func systemdNotifyCount(s *payload.SystemdHealth) int {
	if s == nil || !s.SystemdPresent {
		return 0
	}
	return 1
}

func selinuxNotifyCount(m *payload.SelinuxApparmorBlock) int {
	if m == nil {
		return 0
	}
	if m.SelinuxMode != "" || m.ApparmorSummary != "" {
		return 1
	}
	return 0
}
