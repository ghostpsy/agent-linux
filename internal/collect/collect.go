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
	if hn != nil {
		network.EnrichHostNetwork(hn)
	}
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
	notifyStart("collect_shadow_account_summary")
	sas := identity.CollectShadowAccountSummary()
	notifyDone("collect_shadow_account_summary", shadowNotifyCount(sas), shadowNotifyError(sas))
	notifyStart("collect_duplicate_uid_gid")
	dupUG := identity.CollectDuplicateUidGid()
	notifyDone("collect_duplicate_uid_gid", duplicateIDNotifyCount(dupUG), dupUG.Error)
	notifyStart("collect_password_policy_fingerprint")
	ppf := identity.CollectPasswordPolicyFingerprint()
	notifyDone("collect_password_policy_fingerprint", passwordPolicyNotifyCount(ppf), ppf.Error)
	notifyStart("collect_sudoers_audit")
	sau := identity.CollectSudoersAudit()
	notifyDone("collect_sudoers_audit", len(sau.FilesScanned), sau.Error)
	notifyStart("collect_packages_updates")
	pu, puErr := software.CollectPackagesUpdates()
	notifyDone("collect_packages_updates", packagesPendingUpdatesCount(pu), puErr)
	notifyStart("collect_host_backup")
	hb := software.CollectHostBackup()
	notifyDone("collect_host_backup", len(hb.ToolsDetected), hostBackupLogError(hb))
	notifyStart("collect_web_db_servers_fingerprint")
	wdbf := software.CollectWebDbServersFingerprint()
	notifyDone("collect_web_db_servers_fingerprint", webDbServersNotifyCount(wdbf), "")
	notifyStart("collect_redis_exposure_fingerprint")
	redisF := software.CollectRedisExposureFingerprint()
	notifyDone("collect_redis_exposure_fingerprint", redisExposureNotifyCount(redisF), "")
	notifyStart("collect_cron_timers_inventory")
	cti := software.CollectCronTimersInventory()
	notifyDone("collect_cron_timers_inventory", cronTimersNotifyCount(cti), cti.Error)
	notifyStart("collect_cups_exposure_fingerprint")
	cupsF := software.CollectCupsExposureFingerprint()
	notifyDone("collect_cups_exposure_fingerprint", cupsExposureNotifyCount(cupsF), "")
	notifyStart("collect_mta_fingerprint")
	mtaF := software.CollectMtaFingerprint()
	notifyDone("collect_mta_fingerprint", mtaNotifyCount(mtaF), "")
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
	notifyStart("collect_tcp_wrappers_fingerprint")
	tw := network.CollectTcpWrappersFingerprint()
	notifyDone("collect_tcp_wrappers_fingerprint", tcpWrappersNotifyCount(tw), tw.Error)
	notifyStart("collect_legacy_insecure_services")
	leg := network.CollectLegacyInsecureServices()
	notifyDone("collect_legacy_insecure_services", legacyInsecureNotifyCount(leg), leg.Error)
	notifyStart("collect_host_path")
	hp := filesystem.CollectHostPath()
	notifyDone("collect_host_path", len(hp.Entries), hp.Error)
	notifyStart("collect_host_suid")
	hsuid := filesystem.CollectHostSuid()
	notifyDone("collect_host_suid", len(hsuid.Items), hsuid.Error)
	notifyStart("collect_mount_options_audit")
	moa := filesystem.CollectMountOptionsAudit()
	notifyDone("collect_mount_options_audit", len(moa.Paths), moa.Error)
	notifyStart("collect_path_permissions_audit")
	ppa := filesystem.CollectPathPermissionsAudit()
	notifyDone("collect_path_permissions_audit", pathPermissionsNotifyCount(ppa), ppa.Error)
	notifyStart("collect_usb_storage_posture")
	usbp := filesystem.CollectUsbStoragePosture()
	notifyDone("collect_usb_storage_posture", len(usbp.ModprobeFragmentLinesSample), usbp.Error)
	notifyStart("collect_file_integrity_tooling")
	fim := filesystem.CollectFileIntegrityTooling()
	notifyDone("collect_file_integrity_tooling", len(fim.EvidencePaths)+len(fim.SystemdUnitsSample), fim.Error)
	notifyStart("collect_crypt_storage_hint")
	csh := filesystem.CollectCryptStorageHint()
	notifyDone("collect_crypt_storage_hint", csh.CrypttabEntryCount+csh.LsblkCryptVolumeCount, csh.Error)
	notifyStart("collect_nfs_exports_fingerprint")
	nfsx := filesystem.CollectNfsExportsFingerprint()
	notifyDone("collect_nfs_exports_fingerprint", len(nfsx.Entries), nfsx.Error)
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
			HostUsersSummary:          hus,
			HostSSH:                   hs,
			ShadowAccountSummary:      sas,
			DuplicateUidGid:           dupUG,
			PasswordPolicyFingerprint: ppf,
			SudoersAudit:              sau,
		},
		FileSystemAndStorage: payload.FileSystemAndStorageComponent{
			HostDisk:              hd,
			HostPath:              hp,
			HostSuid:              hsuid,
			MountOptionsAudit:     moa,
			PathPermissionsAudit:  ppa,
			UsbStoragePosture:     usbp,
			FileIntegrityTooling:  fim,
			CryptStorageHint:      csh,
			NfsExportsFingerprint: nfsx,
		},
		NetworkAndHostFirewall: payload.NetworkAndHostFirewallComponent{
			Listeners:              listeners,
			HostNetwork:            hn,
			Firewall:               fw,
			TcpWrappersFingerprint: tw,
			LegacyInsecureServices: leg,
		},
		SoftwarePackagesAndApplications: payload.SoftwarePackagesAndApplicationsComponent{
			Services:                 servicesBlock,
			PackagesUpdates:          pu,
			HostBackup:               hb,
			HostRuntimes:             softwarePackagesHostRuntimes(hr),
			WebDbServersFingerprint:  wdbf,
			RedisExposureFingerprint: redisF,
			CronTimersInventory:      cti,
			CupsExposureFingerprint:  cupsF,
			MtaFingerprint:           mtaF,
		},
		ContainerAndCloudNativeLinux: payload.ContainerAndCloudNativeLinuxComponent{
			HostRuntimes: containerCloudHostRuntimes(hr),
		},
		LoggingAndSystemAuditing: payload.LoggingAndSystemAuditingComponent{},
		Cryptography:             payload.CryptographyComponent{},
		SecurityFrameworksAndMalwareDefense: payload.SecurityFrameworksAndMalwareDefenseComponent{},
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

func shadowNotifyCount(s *payload.ShadowAccountSummary) int {
	if s == nil || !s.ShadowReadable {
		return 0
	}
	return 1
}

func shadowNotifyError(s *payload.ShadowAccountSummary) string {
	if s == nil {
		return ""
	}
	return s.Error
}

func duplicateIDNotifyCount(d *payload.DuplicateUidGid) int {
	if d == nil {
		return 0
	}
	return d.DuplicateUidCount + d.DuplicateGidCount
}

func passwordPolicyNotifyCount(p *payload.PasswordPolicyFingerprint) int {
	if p == nil {
		return 0
	}
	return len(p.PwqualityKeys) + len(p.PamPasswordRequisiteLines)
}

func pathPermissionsNotifyCount(p *payload.PathPermissionsAudit) int {
	if p == nil {
		return 0
	}
	n := len(p.WorldWritableDirsSample) + len(p.SgidItemsSample) + len(p.UnownedFilesSample)
	if p.TmpStickyBitPresent != nil {
		n++
	}
	return n
}

func tcpWrappersNotifyCount(t *payload.TcpWrappersFingerprint) int {
	if t == nil {
		return 0
	}
	return t.HostsAllowLineCount + t.HostsDenyLineCount
}

func legacyInsecureNotifyCount(l *payload.LegacyInsecureServices) int {
	if l == nil {
		return 0
	}
	n := 0
	if l.TelnetSuspected {
		n++
	}
	if l.RshSuspected {
		n++
	}
	if l.RloginSuspected {
		n++
	}
	if l.RexecSuspected {
		n++
	}
	if l.VsftpdSuspected {
		n++
	}
	if l.ProftpdSuspected {
		n++
	}
	if l.InetdConfPresent {
		n++
	}
	return n
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

func webDbServersNotifyCount(w *payload.WebDbServersFingerprint) int {
	if w == nil {
		return 0
	}
	n := 0
	if w.NginxServerTokens != "" || w.NginxConfigPathUsed != "" {
		n++
	}
	if w.ApacheServerTokens != "" || w.ApacheConfigPathUsed != "" {
		n++
	}
	if w.MysqlBindAddress != "" || w.MysqlConfigPathUsed != "" {
		n++
	}
	if w.PostgresqlListenAddresses != "" || w.PostgresqlConfigPathUsed != "" {
		n++
	}
	return n
}

func redisExposureNotifyCount(r *payload.RedisExposureFingerprint) int {
	if r == nil {
		return 0
	}
	if r.ConfigPathUsed != "" || r.UnitActiveState != "" {
		return 1
	}
	return 0
}

func cronTimersNotifyCount(c *payload.CronTimersInventory) int {
	if c == nil {
		return 0
	}
	return c.SystemCrontabLineCount + c.UserCrontabsPresentCount + c.SystemdTimersCount
}

func cupsExposureNotifyCount(c *payload.CupsExposureFingerprint) int {
	if c == nil {
		return 0
	}
	if len(c.ListenLinesSample)+len(c.WebInterfaceLinesSample) > 0 || c.UnitActiveState != "" {
		return 1
	}
	return 0
}

func mtaNotifyCount(m *payload.MtaFingerprint) int {
	if m == nil {
		return 0
	}
	if m.DetectedMta != "" && m.DetectedMta != "none" {
		return 1
	}
	return 0
}

// softwarePackagesHostRuntimes is §5 only: interpreter `items` (and optional collection error).
// Docker/kubelet fingerprints are emitted only under container_and_cloud_native_linux.
func softwarePackagesHostRuntimes(hr *payload.HostRuntimes) *payload.HostRuntimes {
	if hr == nil {
		return nil
	}
	if len(hr.Items) == 0 && hr.Error == "" {
		return nil
	}
	return &payload.HostRuntimes{
		Items: hr.Items,
		Error: hr.Error,
	}
}

// containerCloudHostRuntimes is §6 only: Docker and kubelet fingerprints (`items` always empty).
// Omit the whole block when there is no Docker or kubelet signal (JSON {} for the component).
func containerCloudHostRuntimes(hr *payload.HostRuntimes) *payload.HostRuntimes {
	if hr == nil || (hr.Docker == nil && hr.Kubelet == nil) {
		return nil
	}
	return &payload.HostRuntimes{
		Items:   []payload.RuntimeEntry{},
		Docker:  hr.Docker,
		Kubelet: hr.Kubelet,
	}
}
