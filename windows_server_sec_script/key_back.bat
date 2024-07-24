copy r:\ntrights.exe c:\windows\system32 /y
sc config "diagsvc" start=disabled
sc config "RetailDemo" start=disabled
sc config "lltdsvc" start=disabled
sc config "ssh-agent" start=disabled
sc config "pnrpsvc" start=disabled
sc config "p2pimsvc" start=disabled
sc config "pnrpautoreg" start=disabled
sc config "rasauto" start=disabled
sc config "sessionenv" start=disabled
sc config "rpcLocator" start=disabled
sc config "remoteregistry" start=disabled
sc config "remoteaccess" start=disabled
sc config "ssdpsrv" start=disabled
sc config "upnphost" start=disabled


@echo off
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" /v Disabled /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v Enabled /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v Enabled /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" /v DefaultSecureProtocols /t REG_DWORD /d 800 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" /v SchUseStrongCrypto /t REG_DWORD /d 1 /f
REG ADD "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD "HKey_Local_Machine\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\OLE" /v EnableDCOM /t REG_SZ /d N /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v crashonauditfail /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v CrashOnAuditFail /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v MaxDevicePasswordFailedAttempts /t REG_DWORD /d 9 /f 
REG ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
REG ADD "HKey_Local_Machine\System\CurrentControlSet\Services\LanManServer\Parameters" /v AutoDisconnect /t REG_DWORD /d 10 /f
REG ADD "HKey_Local_Machine\System\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionPipes /t REG_MULTI_SZ /F
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM /t REG_SZ /d O:BAG:BAD:(A;;RC;;;BA) /f
REG ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionShares /t  REG_MULTI_SZ /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v SubmitControl /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\" /v ForceGuest /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\" /v UseMachineId /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA\MSV1_0" /v allownullsessionfallback /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA\pku2u" /v AllowOnlineID /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 0x7ffffffc /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\ControL\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\ControL\Lsa" /v  LmCompatibilityLevel  /t REG_DWORD /d 5 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinServerSec /t REG_DWORD /d 0x20080000 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NtlmMinClientSec /t REG_DWORD /d 0x20080000 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v ObCaseInsensitive /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 1 /f 
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f  
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f  
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 3 /f   
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableInstallerDetection /t REG_DWORD /d 1 /f  
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableSecureUIAPaths /t REG_DWORD /d 1 /f  
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableVirtualization /t REG_DWORD /d 1 /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bowser" /v Start /t REG_DWORD /d 4 /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\IISADMIN" /v Start /t REG_DWORD /d 4 /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\irmon:Start" /v Start /t REG_DWORD /d 4 /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess" /v Start /t REG_DWORD /d 4 /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\FTPSV" /v Start /t REG_DWORD /d 4 /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sshd" /v Start /t REG_DWORD /d 4 /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPsvc" /v Start /t REG_DWORD /d 4 /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2psvc" /v Start /t REG_DWORD /d 4 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\p2pimsvc" /v Start /t REG_DWORD /d 4 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PNRPAutoReg" /v Start /t REG_DWORD /d 4 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TermService" /v Start /t REG_DWORD /d 4 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RpcLocator" /v Start /t REG_DWORD /d 4 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteAccess" /v Start /t REG_DWORD /d 4 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\simptcp" /v Start /t REG_DWORD /d 4 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer" /v Start /t REG_DWORD /d 4 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP" /v Start /t REG_DWORD /d 4 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMSvc" /v Start /t REG_DWORD /d 4 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WerSvc" /v Start /t REG_DWORD /d 4 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v Start /t REG_DWORD /d 4 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WpnService" /v Start /t REG_DWORD /d 4 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC:Start" /v Start /t REG_DWORD /d 4 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v Start /t REG_DWORD /d 4 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v Start /t REG_DWORD /d 4 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XblGameSav" /v Start /t REG_DWORD /d 4 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v Start /t REG_DWORD /d 4 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v EnableFirewall /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v DefaultOutboundAction /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v DefaultInboundAction /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v DisableNotifications /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" /v LogFileSize /t REG_DWORD /d 0x00004000 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" /v LogDroppedPackets /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v LogSuccessfulConnections /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v EnableFirewall /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v DefaultInboundAction /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v DefaultOutboundAction /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile: /v DisableNotifications /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v LogFileSize /t REG_DWORD /d 0x00004000 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v LogDroppedPackets /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v LogSuccessfulConnections /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v EnableFirewall /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v DefaultInboundAction /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v DefaultOutboundAction /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v DisableNotifications /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v LogSuccessfulConnections /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging" /v LogFileSize /t REG_DWORD /d 0x00004000 /f

mkdir %windir%\system32\LogFiles\Firewall\domain
Netsh advfirewall set domainprofile logging filename %windir%\system32\LogFiles\Firewall\domainfw.log

mkdir %windir%\system32\LogFiles\Firewall\private
Netsh advfirewall set privateprofile logging filename %windir%\system32\LogFiles\Firewall\private\privatefw.log

mkdir %windir%\system32\LogFiles\Firewall\public
Netsh advfirewall set publicprofile logging filename %windir%\system32\LogFiles\Firewall\public\publicfw.log



@echo off
REM:Ensure 'Network access: Remotely accessible registry paths and sub-paths' is configured reg import listed below  
reg import R:\machine.reg 
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
net config server /hidden:yes
Pause