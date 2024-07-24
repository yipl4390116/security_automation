copy r:\ntrights.exe c:\windows\system32 /y
sc config "diagsvc" start=disabled
sc config "RetailDemo" start=disabled
sc config "lltdsvc" start=disabled
sc config "ssh-agent" start=disabled
sc config "pnrpsvc" start=disabled
sc config "p2pimsvc" start=disabled
sc config "pnrpautoreg" start=disabledWDigest"
sc config "rasauto" start=disabledWDigest"
sc config "sessionenv" start=disabled
sc config "rpcLocator" start=disabled
sc config "remoteregistry" start=disabled
sc config "remoteaccess" start=disabled
sc config "ssdpsrv" start=disabled
sc config "upnphost" start=disabled


@echo off
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" /v Disabled /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v Enabled /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v Enabled /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" /v DefaultSecureProtocols /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /v SchUseStrongCrypto /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" /v SchUseStrongCrypto /f
REG DELETE "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v DisabledByDefault /f
REG DELETE "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v DisabledByDefault /f
REG DELETE "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v DisabledByDefault /f
REG DELETE "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v DisabledByDefault /f
REG DELETE "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v DisabledByDefault /f
REG DELETE "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v DisabledByDefault /f
REG DELETE "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v DisabledByDefault /f
REG DELETE "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v DisabledByDefault /f
REG DELETE "HKEY_LOCAL_MACHINE\Software\Microsoft\OLE" /v EnableDCOM /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v crashonauditfail /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v CrashOnAuditFail /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v MaxDevicePasswordFailedAttempts /f 
REG DELETE "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /f
REG DELETE "HKey_Local_Machine\System\CurrentControlSet\Services\LanManServer\Parameters" /v AutoDisconnect /f
REG DELETE "HKey_Local_Machine\System\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionPipes /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM O:BAG:BAD:(A;;RC;;;BA) /f
REG DELETE "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionShares /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v SubmitControl /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RestrictNullSessAccess /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\" /v ForceGuest /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\" /v UseMachineId /f
REG DELETE "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA\MSV1_0" /v allownullsessionfallback /f
REG DELETE "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA\pku2u" /v AllowOnlineID /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\ControL\Lsa" /v NoLMHash /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\ControL\Lsa" /v  LmCompatibilityLevel /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinServerSec /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NtlmMinClientSec /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v ObCaseInsensitive /f
REG DELETE "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" /v ProtectionMode /f 
REG DELETE "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /f  
REG DELETE "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /f  
REG DELETE "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /f   
REG DELETE "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /f  
REG DELETE "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableSecureUIAPaths /f  
REG DELETE "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /f  
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /f 
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /f 
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bowser" /v Start /f 
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IISADMIN" /v Start /f 
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\irmon:Start" /v Start /f 
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess" /v Start /f 
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FTPSV" /v Start /f 
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sshd" /v Start /f 
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPsvc" /v Start /f 
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2psvc" /v Start /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2pimsvc" /v Start /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPAutoReg" /v Start /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService" /v Start /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcLocator" /v Start /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess" /v Start /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer" /v Start /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP" /v Start /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMSvc" /v Start /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc" /v Start /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v Start /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnService" /v Start /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC:Start" /v Start /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v Start /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v Start /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblGameSav" /v Start /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v Start /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v Start /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\kernel" /v DisableExceptionChainValidation /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v NodeType /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /f
REG DELETE "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters" /v DisableIPSourceRouting /f
REG DELETE "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters" /v DisableIPSourceRouting /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" /v DisableSavePassword /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v EnableICMPRedirect /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v KeepAliveTime /F
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v NoNameReleaseOnDemand /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDllSearchMode /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" /v TcpMaxDataRetransmissions /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxDataRetransmissions /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v AllowInsecureGuestAuth /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v AllowLLTDIOOnDomain /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v AllowLLTDIOOnPublicNet /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v EnableLLTDIO /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v ProhibitLLTDIOOnPrivateNet /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_AllowNetBridge_NLA /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v Hidden /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" /v "\\*\SYSVOL" "RequireMutualAuthentication=1" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" /v "\\*\NETLOGON" "RequireMutualAuthentication=1" /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy:fMinimizeConnections" /v Hidden /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" /v AllowEncryptionOracle /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v EnableVirtualizationBasedSecurity /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v HypervisorEnforcedCodeIntegrity /f
645 REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WiHKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policyndows\DeviceGuard" /v HVCIMATRequired /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v LsaCfgFlags /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v ConfigureSystemGuardLaunch /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" /v DriverLoadPolicy /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableCdp /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v DisableWebPnPDownload /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard" /v ExitOnMSICW /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoOnlinePrintsWizard /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoPublishingWizard /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Messenger\Client" /v CEIP /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v CEIPEnable /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v DoReport /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v BlockUserFromShowingAccountDetailsOnSignin /f 
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v DontEnumerateConnectedUsers /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v EnumerateLocalUsers /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v AllowDomainPINLogon /f
REG DELETE "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\ACSettingIndex" /v ACSettingIndex /f 
REG DELETE "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9\DCSettingIndex" /v DCSettingIndex /f 
REG DELETE "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v DCSettingIndex /f 
REG DELETE "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v ACSettingIndex /f 
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowUnsolicited /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v EnableAuthEpResolution /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v RestrictRemoteClients /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v DisableQueryRemoteServer /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" /v Enabled /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" /v Enabled /f
REG DELETE "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" /v AllowSharedLocalAppData /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Appx" /v BlockNonAdminUserInstall /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoiceAboveLock /f 
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Connect" /v RequirePinForPairing /f 
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUIEnumerateAdministrators" /v RequirePinForPairing /f 
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v NoLocalPasswordResetQuestions /f 
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /f 
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DisableEnterpriseAuthProxy /f 
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /f 
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v AllowBuildPreview /f 
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" /v Retention /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" /v Retention /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" /v Retention /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" /v Retention /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoDataExecutionPrevention /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoHeapTerminationOnCorruption /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v PreXPSP2ShellProtocolBehavior /f






REM:Ensure 'Network access: Remotely accessible registry paths and sub-paths' is configured reg import listed below  
cd R:\PHT-UTIL\
reg import R:\PHT-UTIL\machine.reg 
::net accounts /uniquepw:24 (Leave config up to client)
::net accounts /lockoutthreshold:10 (Leave config up to client)
::net accounts /lockoutduration:15 (Leave config up to client)
ntrights -r SeNetworkLogonRight -u "Backup Operators"
ntrights +r SeNetworkLogonRight -u "Administrators"
ntrights +r SeIncreaseQuotaPrivilege -u "Administrators"
ntrights +r SeInteractiveLogonRight -u "Administrators"
ntrights -r SeInteractiveLogonRight -u "guest"
ntrights -r SeInteractiveLogonRight -u "Backup Operators"
ntrights -r SeRemoteInteractiveLogonRight -u "guest"
ntrights -r SeBackupPrivilege -u "guest"
ntrights -r SeChangeNotifyPrivilege -u "guest"
ntrights -r SeSystemtimePrivilege -u "guest"
ntrights +r SeDenyNetworkLogonRight -u "guest"
ntrights -r SeCreateTokenPrivilege -u "guest"
ntrights -r SeCreateTokenPrivilege -u "users"
ntrights -r SeCreateTokenPrivilege -u "administrators"
ntrights -r SeCreateGlobalPrivilege -u "guest"
ntrights -r SeDebugPrivilege -u "guest"
ntrights -r SeDenyNetworkLogonRight -u "guest"
ntrights -r SeDenyBatchLogonRight -u "guest"
ntrights -r SeDenyServiceLogonRight -u "guest"	
ntrights -r SeEnableDelegationPrivilege -u "guest"	
ntrights -r SeRemoteShutdownPrivilege -u "guest"
ntrights -r SeAuditPrivilege -u "guest"
ntrights -r SeIncreaseWorkingSetPrivilege -u "guest"
ntrights -r SeLoadDriverPrivilege -u "guest"
ntrights -r SeLockMemoryPrivilege -u "guest"
ntrights -r SeBatchLogonRight -u "guest"
ntrights -r SeServiceLogonRight -u "guest"
ntrights -r SeSecurityPrivilege -u "guest"
ntrights -r SeRelabelPrivilege -u "guest"
ntrights -r SeSystemEnvironmentPrivilege -u "guest"
ntrights -r SeProfileSingleProcessPrivilege -u "guest"
ntrights -r SeSystemProfilePrivilege -u "guest"
ntrights -r SeUndockPrivilege -u "guest"
ntrights -r SeAssignPrimaryTokenPrivilege -u "guest"
ntrights -r SeRestorePrivilege -u "guest"
ntrights -r SeShutdownPrivilege -u "guest"
ntrights -r SeSyncAgentPrivilege -u "guest"
ntrights -r SeTakeOwnershipPrivilege -u "guest"
ntrights -r SeCreatePermanentPrivilege -u "guest"
ntrights -r SeTcbPrivilege -u "guest"
ntrights -r SeMachineAccountPrivilege -u "guest"
ntrights -r SeLockMemoryPrivilege -u "guest"
ntrights -r SeSecurityPrivilege -u "guest"
ntrights -r SeSystemEnvironmentPrivilege -u "guest"
ntrights -r SeManageVolumePrivilege -u "guest"
ntrights -r SeProfileSingleProcessPrivilege -u "guest"
ntrights -r SeUndockPrivilege -u "guest"
ntrights -r SeAssignPrimaryTokenPrivilege -u "guest"
ntrights -r SeRestorePrivilege -u "guest"
ntrights -r SeShutdownPrivilege -u "guest"
ntrights -r SeSyncAgentPrivilege -u "guest"
ntrights -r SeTakeOwnershipPrivilege -u "guest"	

net user guest /active:no

netsh advfirewall>set allprofiles logging allowedconnections enable
netsh advfirewall>set allprofiles logging droppedconnections enable

cd C:\Windows\System32\Winevt\Logs
wevtutil sl Security /ms:1000000000
wevtutil sl System /ms:1000000000
wevtutil sl Application /ms:1000000000
wevtutil sl Setup /ms:1000000000

auditpol /set /subcategory:"Audit Policy Change" /success:enable  /failure:enable 
auditpol /set /subcategory:"Security State Change" /success:enable  /failure:enable 
auditpol /set /subcategory:"Security System Extension" /success:enable  /failure:enable 
auditpol /set /subcategory:"System Integrity" /success:enable  /failure:enable 
auditpol /set /subcategory:"Other System Events" /success:disable  /failure:enable 
auditpol /set /subcategory:"Logon" /success:enable  /failure:enable 
auditpol /set /subcategory:"Logoff" /success:enable  /failure:enable 
auditpol /set /subcategory:"Account Lockout" /success:enable  /failure:enable 
auditpol /set /subcategory:"Special Logon" /success:enable  /failure:enable 
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable  /failure:enable 
auditpol /set /subcategory:"File System" /success:enable  /failure:enable 
auditpol /set /subcategory:"Registry" /success:enable  /failure:enable 
auditpol /set /subcategory:"Kernel Object" /success:enable  /failure:enable 
auditpol /set /subcategory:"SAM" /success:disable  /failure:disable
auditpol /set /subcategory:"Certification Services" /success:enable  /failure:enable 
auditpol /set /subcategory:"Application Generated" /success:enable  /failure:enable 
auditpol /set /subcategory:"Handle Manipulation" /success:disable  /failure:disable 
auditpol /set /subcategory:"File Share" /success:enable  /failure:enable 
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:disable  /failure:disable 
auditpol /set /subcategory:"Filtering Platform Connection" /success:disable  /failure:disable 
auditpol /set /subcategory:"Other Object Access Events" /success:disable  /failure:disable 
auditpol /set /subcategory:"Sensitive Privilege Use" /success:disable  /failure:disable
auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:disable  /failure:disable 
auditpol /set /subcategory:"Other Privilege Use Events" /success:disable  /failure:disable 
auditpol /set /subcategory:"Process Creation" /success:enable  /failure:enable 
auditpol /set /subcategory:"Process Termination" /success:enable  /failure:enable 
auditpol /set /subcategory:"DPAPI Activity" /success:disable  /failure:disable 
auditpol /set /subcategory:"RPC Events" /success:enable  /failure:enable 
auditpol /set /subcategory:"Audit Policy Change" /success:enable  /failure:enable 
auditpol /set /subcategory:"Authentication Policy Change" /success:enable  /failure:enable 
auditpol /set /subcategory:"Authorization Policy Change" /success:enable  /failure:enable 
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:disable  /failure:disable
auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable  /failure:disable 
auditpol /set /subcategory:"Other Policy Change Events" /success:disable  /failure:enable 
auditpol /set /subcategory:"User Account Management" /success:enable  /failure:enable 
auditpol /set /subcategory:"Computer Account Management" /success:enable  /failure:enable 
auditpol /set /subcategory:"Security Group Management" /success:enable  /failure:enable 
auditpol /set /subcategory:"Distribution Group Management" /success:enable  /failure:enable 
auditpol /set /subcategory:"Application Group Management" /success:enable  /failure:enable 
auditpol /set /subcategory:"Other Account Management Events" /success:enable  /failure:enable 
auditpol /set /subcategory:"Directory Service Access" /success:enable  /failure:enable 
auditpol /set /subcategory:"Directory Service Changes" /success:enable  /failure:enable 
auditpol /set /subcategory:"Directory Service Replication" /success:disable  /failure:disable 
auditpol /set /subcategory:"Detailed Directory Service Replication" /success:disable  /failure:disable 
auditpol /set /subcategory:"Credential Validation" /success:enable  /failure:enable 
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable  /failure:enable 
auditpol /set /subcategory:"Other Account Logon Events" /success:enable  /failure:enable 
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable  /failure:enable

Pause