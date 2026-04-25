//go:build linux

package collect

import (
	"context"

	"github.com/ghostpsy/agent-linux/internal/collect/container"
	"github.com/ghostpsy/agent-linux/internal/collect/core"
	"github.com/ghostpsy/agent-linux/internal/collect/crypto_time"
	"github.com/ghostpsy/agent-linux/internal/collect/filesystem"
	"github.com/ghostpsy/agent-linux/internal/collect/firewall"
	"github.com/ghostpsy/agent-linux/internal/collect/identity"
	"github.com/ghostpsy/agent-linux/internal/collect/logging"
	"github.com/ghostpsy/agent-linux/internal/collect/network"
	"github.com/ghostpsy/agent-linux/internal/collect/security"
	"github.com/ghostpsy/agent-linux/internal/collect/software"
	"github.com/ghostpsy/agent-linux/internal/collect/software/apache"
	"github.com/ghostpsy/agent-linux/internal/collect/software/packages"
	"github.com/ghostpsy/agent-linux/internal/collect/software/mysql"
	"github.com/ghostpsy/agent-linux/internal/collect/software/nginx"
	"github.com/ghostpsy/agent-linux/internal/collect/software/ftp"
	"github.com/ghostpsy/agent-linux/internal/collect/software/mongodb"
	"github.com/ghostpsy/agent-linux/internal/collect/software/redis"
	"github.com/ghostpsy/agent-linux/internal/collect/software/postfix"
	"github.com/ghostpsy/agent-linux/internal/payload"
	"github.com/ghostpsy/agent-linux/internal/version"
)

type stubStep struct {
	action string
	run    func() (int, string)
}

// stubBuildPayloadV1 runs registered scan steps (data-driven pipeline). Each step checks ctx before running.
func stubBuildPayloadV1(ctx context.Context, machineUUID string, scanSeq int, observe ActionEventObserver) (payload.V1, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	check := func() error { return ctx.Err() }
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

	var hn *payload.HostNetwork
	var hd *payload.HostDisk
	var hus *payload.HostUsersSummary
	var hs *payload.HostSSH
	var sas *payload.ShadowAccountSummary
	var dupUG *payload.DuplicateUidGid
	var ppf *payload.PasswordPolicyFingerprint
	var sau *payload.SudoersAudit
	var pu *payload.PackagesUpdates
	var hb *payload.HostBackup
	var wdbf *payload.WebDbServersFingerprint
	var redisF *payload.RedisExposureFingerprint
	var cti *payload.CronTimersInventory
	var cupsF *payload.CupsExposureFingerprint
	var mtaF *payload.MtaFingerprint
	var apachePosture *payload.ApacheHttpdPosture
	var nginxPosture *payload.NginxPosture
	var postfixPosture *payload.PostfixPosture
	var ftpPosture *payload.FtpPosture
	var redisPosture *payload.RedisPosture
	var mongodbPosture *payload.MongodbPosture
	var mysqlPosture *payload.MysqlPosture
	var postgresPosture *payload.PostgresPosture
	var dockerPosture *payload.DockerPosture
	var servicesBlock payload.ServicesBlock
	var osInfo payload.OSInfo
	var hostname string
	var fqdn string
	var grubSnap *payload.GrubSnapshot
	var fwBoot *payload.FirmwareBoot
	var sysd *payload.SystemdHealth
	var sysLive *payload.SysctlLiveBlock
	var sysOverlay *payload.SysctlOverlayBlock
	var kmods *payload.KernelModulesBlock
	var mac *payload.SelinuxApparmorBlock
	var hrisk *payload.HighRiskProcessSurface
	var fw *payload.Firewall
	var tw *payload.TcpWrappersFingerprint
	var leg *payload.LegacyInsecureServices
	var hp *payload.HostPath
	var hsuid *payload.HostSuid
	var moa *payload.MountOptionsAudit
	var ppa *payload.PathPermissionsAudit
	var usbp *payload.UsbStoragePosture
	var fim *payload.FileIntegrityTooling
	var csh *payload.CryptStorageHint
	var nfsx *payload.NfsExportsFingerprint
	var hproc *payload.HostProcess
	var hr *payload.HostRuntimes
	var containerWorkloads *payload.ContainerWorkloads
	var hostTime *payload.HostTime
	var cryptoComp payload.CryptographyComponent
	var listeners []payload.Listener
	var logAudit payload.LoggingAndSystemAuditingComponent
	var secFW payload.SecurityFrameworksAndMalwareDefenseComponent

	steps := []stubStep{
		{"collect_host_network", func() (int, string) {
			hn = filesystem.CollectHostNetwork(ctx)
			if hn != nil {
				network.EnrichHostNetwork(ctx, hn)
			}
			return len(hostNetworkInterfaces(hn)), hostNetworkErr(hn)
		}},
		{"collect_host_disk", func() (int, string) {
			hd = filesystem.CollectHostDisk(ctx)
			return len(hostDiskFilesystems(hd)), hostDiskErr(hd)
		}},
		{"collect_host_users_summary", func() (int, string) {
			hus = identity.CollectHostUsersSummary(ctx)
			return len(hostUsersSample(hus)), hostUsersErr(hus)
		}},
		{"collect_host_ssh", func() (int, string) {
			hs = identity.CollectHostSSH(ctx)
			return hostSSHListenCount(hs), hostSSHErr(hs)
		}},
		{"collect_shadow_account_summary", func() (int, string) {
			sas = identity.CollectShadowAccountSummary(ctx)
			return shadowNotifyCount(sas), shadowNotifyError(sas)
		}},
		{"collect_duplicate_uid_gid", func() (int, string) {
			dupUG = identity.CollectDuplicateUidGid(ctx)
			errStr := ""
			if dupUG != nil {
				errStr = dupUG.Error
			}
			return duplicateIDNotifyCount(dupUG), errStr
		}},
		{"collect_password_policy_fingerprint", func() (int, string) {
			ppf = identity.CollectPasswordPolicyFingerprint(ctx)
			return passwordPolicyNotifyCount(ppf), ppf.Error
		}},
		{"collect_sudoers_audit", func() (int, string) {
			sau = identity.CollectSudoersAudit(ctx)
			return len(sau.FilesScanned), sau.Error
		}},
		{"collect_packages_updates", func() (int, string) {
			pu = packages.CollectPackagesUpdates(ctx)
			return packagesPendingUpdatesCount(pu), packagesUpdatesErr(pu)
		}},
		{"collect_host_backup", func() (int, string) {
			hb = software.CollectHostBackup(ctx)
			return len(hb.ToolsDetected), hostBackupLogError(hb)
		}},
		{"collect_web_db_servers_fingerprint", func() (int, string) {
			wdbf = software.CollectWebDbServersFingerprint(ctx)
			return webDbServersNotifyCount(wdbf), ""
		}},
		{"collect_redis_exposure_fingerprint", func() (int, string) {
			redisF = software.CollectRedisExposureFingerprint(ctx)
			return redisExposureNotifyCount(redisF), ""
		}},
		{"collect_cron_timers_inventory", func() (int, string) {
			cti = software.CollectCronTimersInventory(ctx)
			return cronTimersNotifyCount(cti), cti.Error
		}},
		{"collect_cups_exposure_fingerprint", func() (int, string) {
			cupsF = software.CollectCupsExposureFingerprint(ctx)
			return cupsExposureNotifyCount(cupsF), ""
		}},
		{"collect_mta_fingerprint", func() (int, string) {
			mtaF = software.CollectMtaFingerprint(ctx)
			return mtaNotifyCount(mtaF), ""
		}},
		{"collect_services", func() (int, string) {
			servicesBlock = network.CollectServices(ctx)
			return len(servicesBlock.Items), servicesBlock.Error
		}},
		{"collect_postfix_posture", func() (int, string) {
			postfixPosture = postfix.CollectPostfixPosture(ctx, servicesBlock.Items)
			return postfixPostureNotifyCount(postfixPosture), postfixPostureError(postfixPosture)
		}},
		{"collect_ftp_posture", func() (int, string) {
			ftpPosture = ftp.CollectFtpPosture(ctx, servicesBlock.Items)
			if ftpPosture == nil {
				return 0, ""
			}
			return 1, ftpPosture.Error
		}},
		{"collect_redis_posture", func() (int, string) {
			redisPosture = redis.CollectRedisPosture(ctx, servicesBlock.Items)
			if redisPosture == nil {
				return 0, ""
			}
			return 1, redisPosture.Error
		}},
		{"collect_mongodb_posture", func() (int, string) {
			mongodbPosture = mongodb.CollectMongodbPosture(ctx, servicesBlock.Items)
			if mongodbPosture == nil {
				return 0, ""
			}
			return 1, mongodbPosture.Error
		}},
		{"collect_mysql_posture", func() (int, string) {
			mysqlPosture = mysql.CollectMysqlPosture(ctx, servicesBlock.Items)
			return mysqlPostureNotifyCount(mysqlPosture), mysqlPostureError(mysqlPosture)
		}},
		{"collect_os_info", func() (int, string) {
			osInfo, hostname = core.CollectOSInfo(ctx)
			fqdn = core.CollectFqdn(ctx, hostname)
			return nonEmptyOSInfoFields(osInfo), ""
		}},
		{"collect_grub", func() (int, string) {
			grubSnap = core.CollectGrubSnapshot(ctx)
			return grubNotifyCount(grubSnap), grubSnap.Error
		}},
		{"collect_firmware_boot", func() (int, string) {
			fwBoot = core.CollectFirmwareBoot(ctx)
			return firmwareNotifyCount(fwBoot), fwBoot.Error
		}},
		{"collect_systemd_health", func() (int, string) {
			sysd = core.CollectSystemdHealth(ctx)
			return systemdNotifyCount(sysd), sysd.Error
		}},
		{"collect_sysctl_live", func() (int, string) {
			sysLive = core.CollectSysctlLiveProfile(ctx)
			return len(sysLive.Items), sysLive.Error
		}},
		{"collect_sysctl_overlay", func() (int, string) {
			sysOverlay = core.CollectSysctlOverlay(ctx)
			return len(sysOverlay.Drift), sysOverlay.Error
		}},
		{"collect_kernel_modules", func() (int, string) {
			kmods = core.CollectKernelModules(ctx)
			return len(kmods.Names), kmods.Error
		}},
		{"collect_selinux_apparmor", func() (int, string) {
			mac = core.CollectSelinuxApparmor(ctx)
			return selinuxNotifyCount(mac), mac.Error
		}},
		{"collect_security_frameworks_and_malware", func() (int, string) {
			secFW = security.Collect(ctx, mac)
			return securityFrameworksNotifyCount(secFW), securityFrameworksFirstError(secFW)
		}},
		{"collect_high_risk_process", func() (int, string) {
			hrisk = core.CollectHighRiskProcessSurface(ctx)
			return len(hrisk.Items), hrisk.Error
		}},
		{"collect_firewall", func() (int, string) {
			fw = firewall.CollectFirewall(ctx)
			return firewallRuleCount(fw), firewallError(fw)
		}},
		{"collect_tcp_wrappers_fingerprint", func() (int, string) {
			tw = network.CollectTcpWrappersFingerprint(ctx)
			return tcpWrappersNotifyCount(tw), tw.Error
		}},
		{"collect_legacy_insecure_services", func() (int, string) {
			leg = network.CollectLegacyInsecureServices(ctx)
			return legacyInsecureNotifyCount(leg), leg.Error
		}},
		{"collect_host_path", func() (int, string) {
			hp = filesystem.CollectHostPath(ctx)
			return len(hp.Entries), hp.Error
		}},
		{"collect_host_suid", func() (int, string) {
			hsuid = filesystem.CollectHostSuid(ctx)
			return len(hsuid.Items), hsuid.Error
		}},
		{"collect_mount_options_audit", func() (int, string) {
			moa = filesystem.CollectMountOptionsAudit(ctx)
			return len(moa.Paths), moa.Error
		}},
		{"collect_path_permissions_audit", func() (int, string) {
			ppa = filesystem.CollectPathPermissionsAudit(ctx)
			return pathPermissionsNotifyCount(ppa), ppa.Error
		}},
		{"collect_usb_storage_posture", func() (int, string) {
			usbp = filesystem.CollectUsbStoragePosture(ctx)
			return len(usbp.ModprobeFragmentLinesSample), usbp.Error
		}},
		{"collect_file_integrity_tooling", func() (int, string) {
			fim = filesystem.CollectFileIntegrityTooling(ctx)
			return len(fim.EvidencePaths) + len(fim.SystemdUnitsSample), fim.Error
		}},
		{"collect_crypt_storage_hint", func() (int, string) {
			csh = filesystem.CollectCryptStorageHint(ctx)
			return csh.CrypttabEntryCount + csh.LsblkCryptVolumeCount, csh.Error
		}},
		{"collect_nfs_exports_fingerprint", func() (int, string) {
			nfsx = filesystem.CollectNfsExportsFingerprint(ctx)
			return len(nfsx.Entries), nfsx.Error
		}},
		{"collect_host_process", func() (int, string) {
			hproc = core.CollectHostProcess(ctx)
			return len(hproc.Top), hproc.Error
		}},
		{"collect_host_runtimes", func() (int, string) {
			hr = software.CollectHostRuntimes(ctx)
			return len(hr.Items), hr.Error
		}},
		{"collect_host_time", func() (int, string) {
			hostTime = crypto_time.CollectHostTime(ctx)
			return 1, ""
		}},
		{"collect_cryptography", func() (int, string) {
			cryptoComp = payload.CryptographyComponent{}
			if inv := crypto_time.CollectLocalTlsCertInventory(ctx); inv != nil {
				cryptoComp.LocalTlsCertInventory = inv
			}
			return cryptographyNotifyCount(cryptoComp), ""
		}},
		{"collect_listeners", func() (int, string) {
			listeners = firewall.ApplyFirewallRuleToListeners(ctx, network.CollectListeners(ctx, hn), fw)
			if listeners == nil {
				listeners = []payload.Listener{}
			}
			return len(listeners), ""
		}},
		// WAN probe is performed API-side after LLM analysis (uses probe_targets from host_network).
		{"collect_postgres_posture", func() (int, string) {
			postgresPosture = software.CollectPostgresPosture(ctx, servicesBlock.Items, listeners)
			return postgresPostureNotifyCount(postgresPosture), postgresPostureError(postgresPosture)
		}},
		{"collect_docker_posture", func() (int, string) {
			dockerPosture = software.CollectDockerPosture(ctx)
			return dockerPostureNotifyCount(dockerPosture), dockerPostureError(dockerPosture)
		}},
		{"collect_container_workloads", func() (int, string) {
			containerWorkloads = container.CollectContainerWorkloads(ctx)
			return containerWorkloadsNotifyCount(containerWorkloads), ""
		}},
		{"collect_nginx_posture", func() (int, string) {
			nginxPosture = nginx.CollectNginxPosture(ctx, servicesBlock.Items, listeners)
			return nginxPostureNotifyCount(nginxPosture), nginxPostureError(nginxPosture)
		}},
		{"collect_apache_httpd_posture", func() (int, string) {
			apachePosture = apache.CollectApacheHttpdPosture(ctx, servicesBlock.Items, listeners)
			return apacheHttpdNotifyCount(apachePosture), apacheHttpdError(apachePosture)
		}},
		{"collect_logging_and_system_auditing", func() (int, string) {
			logAudit = logging.CollectLoggingAndSystemAuditing(ctx)
			return loggingAuditNotifyCount(logAudit), loggingAuditFirstError(logAudit)
		}},
	}

	for _, step := range steps {
		if err := check(); err != nil {
			return payload.V1{}, err
		}
		notifyStart(step.action)
		items, errStr := step.run()
		notifyDone(step.action, items, errStr)
	}

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
			ApacheHttpdPosture:       apachePosture,
			NginxPosture:             nginxPosture,
			PostfixPosture:           postfixPosture,
			FtpPosture:               ftpPosture,
			RedisPosture:             redisPosture,
			MongodbPosture:           mongodbPosture,
			MysqlPosture:             mysqlPosture,
			PostgresPosture:          postgresPosture,
			DockerPosture:            dockerPosture,
		},
		ContainerAndCloudNativeLinux: payload.ContainerAndCloudNativeLinuxComponent{
			HostRuntimes:      containerCloudHostRuntimes(hr),
			ContainerWorkloads: containerWorkloads,
		},
		LoggingAndSystemAuditing:            logAudit,
		Cryptography:                        cryptoComp,
		SecurityFrameworksAndMalwareDefense: secFW,
		Other:                               payload.OtherComponent{},
	}
	return payload.V1{
		SchemaVersion: 1,
		MachineUUID:   machineUUID,
		ScanSeq:       scanSeq,
		Hostname:      hostname,
		Fqdn:          fqdn,
		AgentVersion:  version.Version,
		Components:    components,
	}, nil
}
