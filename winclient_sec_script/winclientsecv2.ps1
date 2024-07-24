robocopy R:\poldef\ C:\Windows\PolicyDefinitions\ /v /w:1 /r:1 
robocopy R:\poldef\en-US C:\Windows\PolicyDefinitions\en-US /v /w:1 /r:1 

cd R:\LGPO_30\
.\LGPO.exe /g R:\

Set-Service -Name diagsvc -StartupType Disabled
Set-Service -Name RetailDemo -StartupType Disabled
Set-Service -Name ssh-agent -StartupType Disabled
Set-Service -Name pnrpsvc -StartupType Disabled
Set-Service -Name p2pimsvc -StartupType Disabled
Set-Service -Name pnrpautoreg -StartupType Disabled
Set-Service -Name rasauto -StartupType Disabled
Set-Service -Name sessionenv -StartupType Disabled
Set-Service -Name rpcLocator -StartupType Disabled
Set-Service -Name remoteregistry -StartupType Disabled
Set-Service -Name remoteaccess -StartupType Disabled
Set-Service -Name ssdpsrv -StartupType Disabled
Set-Service -Name upnphost -StartupType Disabled
Set-Service -Name bowser -StartupType Disabled
Set-Service -Name IISADMIN -StartupType Disabled
Set-Service -Name irmon -StartupType Disabled
Set-Service -Name SharedAccess -StartupType Disabled
Set-Service -Name FTPSV -StartupType Disabled
Set-Service -Name sshd -StartupType Disabled
Set-Service -Name PNRPsvc -StartupType Disabled
Set-Service -Name p2psvc -StartupType Disabled
Set-Service -Name p2pimsvc -StartupType Disabled
Set-Service -Name PNRPAutoReg -StartupType Disabled
Set-Service -Name TermService -StartupType Disabled
Set-Service -Name RpcLocator -StartupType Disabled
Set-Service -Name RemoteAccess -StartupType Disabled
Set-Service -Name SNMP -StartupType Disabled
Set-Service -Name WMSvc -StartupType Disabled
Set-Service -Name WerSvc -StartupType Disabled
Set-Service -Name WMPNetworkSvc -StartupType Disabled
Set-Service -Name WpnService -StartupType Disabled
Set-Service -Name W3SVC -StartupType Disabled
Set-Service -Name XboxGipSvc -StartupType Disabled
Set-Service -Name XblAuthManager -StartupType Disabled
Set-Service -Name XblGameSav -StartupType Disabled
Set-Service -Name XboxNetApiSvc -StartupType Disabled

<# Write-Host 'Windows Internet Explorer: Activate TLS 1.2 only #>
New-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'SecureProtocols' -value $defaultSecureProtocolsSum -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -name 'SchUseStrongCrypto' -value 1 -PropertyType 'DWord' -Force | Out-Null

<# Disable SSL 2.0 (PCI Compliance) #>
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'SSL 2.0 has been disabled.'

<#Disable SSL 3.0 (PCI Compliance) and enable "Poodle" protection#>
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'SSL 3.0 has been disabled.'

<# Disable TLS 1.0 for client and server SCHANNEL communications#>
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.0 has been disabled.'

<# Add and Disable TLS 1.1 for client and server SCHANNEL communications#>
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.1 has been disabled.'

<# Add and Enable TLS 1.2 for client and server SCHANNEL communications#>
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.2 has been enabled.'

<# Re-create the ciphers key.3#>
New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers' -Force | Out-Null

<# Disable insecure/weak ciphers.#>
$insecureCiphers = @(
  'DES 56/56',
  'NULL',
  'RC2 128/128',
  'RC2 40/128',
  'RC2 56/128',
  'RC4 40/128',
  'RC4 56/128',
  'RC4 64/128',
  'RC4 128/128',
  'Triple DES 168'
)
Foreach ($insecureCipher in $insecureCiphers) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey($insecureCipher)
  $key.SetValue('Enabled', 0, 'DWord')
  $key.close()
  Write-Host "Weak cipher $insecureCipher has been disabled."
}

<# Set hashes configuration.#>
New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5' -name Enabled -value 0 -PropertyType 'DWord' -Force | Out-Null
 
$secureHashes = @(
  'SHA',
  'SHA256',
  'SHA384',
  'SHA512'
)
Foreach ($secureHash in $secureHashes) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes', $true).CreateSubKey($secureHash)
  New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$secureHash" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
  $key.close()
  Write-Host "Hash $secureHash has been enabled."
}

# Set KeyExchangeAlgorithms configuration.
New-Item 'HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms' -Force | Out-Null
$secureKeyExchangeAlgorithms = @(
  'Diffie-Hellman',
  'ECDH',
  'PKCS'
)
Foreach ($secureKeyExchangeAlgorithm in $secureKeyExchangeAlgorithms) {
  $key = (Get-Item HKLM:\).OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms', $true).CreateSubKey($secureKeyExchangeAlgorithm)
  New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$secureKeyExchangeAlgorithm" -name 'Enabled' -value '0xffffffff' -PropertyType 'DWord' -Force | Out-Null
  $key.close()
  Write-Host "KeyExchangeAlgorithm $secureKeyExchangeAlgorithm has been enabled."
}
 
<# Add and Disable SMB V1 Windows 10#>
Dism /online /Disable-Feature /FeatureName:"SMB1Protocol"
Dism /online /Disable-Feature /FeatureName:"SMB1Protocol-Client"
Dism /online /Disable-Feature /FeatureName:"SMB1Protocol-Server"

<#Enable LSA Protection against Mimikatz, To enable the audit mode for Lsass.exe#> 
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f

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

<#Disable NetBIOS over TCP/IPfor all adapters on system#> 
$adapters=(gwmi win32_networkadapterconfiguration )
Foreach ($adapter in $adapters){
  Write-Host $adapter
  $adapter.settcpipnetbios(2)
}

.\ntrights.exe -r SeNetworkLogonRight -u "Backup Operators"
.\ntrights.exe +r SeNetworkLogonRight -u "Administrators"
.\ntrights.exe +r SeIncreaseQuotaPrivilege -u "Administrators"
.\ntrights.exe -r SeInteractiveLogonRight -u "Administrators"
.\ntrights.exe -r SeInteractiveLogonRight -u "guest"
.\ntrights.exe -r SeInteractiveLogonRight -u "Backup Operators"
.\ntrights.exe -r SeRemoteInteractiveLogonRight -u "guest"
.\ntrights.exe -r SeBackupPrivilege -u "guest"
.\ntrights.exe -r SeChangeNotifyPrivilege -u "guest"
.\ntrights.exe -r SeSystemtimePrivilege -u "guest"
.\ntrights.exe +r SeDenyNetworkLogonRight -u "guest"
.\ntrights.exe -r SeCreateTokenPrivilege -u "guest"
.\ntrights.exe -r SeCreateTokenPrivilege -u "users"
.\ntrights.exe -r SeCreateTokenPrivilege -u "administrators"
.\ntrights.exe -r SeCreateGlobalPrivilege -u "guest"
.\ntrights.exe +r SeDebugPrivilege -u "guest"
.\ntrights.exe +r SeDenyNetworkLogonRight -u "guest"
.\ntrights.exe +r SeDenyBatchLogonRight -u "guest"
.\ntrights.exe +r SeDenyServiceLogonRight -u "guest"
.\ntrights.exe +r SeDenyRemoteInteractiveLogonRight -u "guest"  
.\ntrights.exe -r SeEnableDelegationPrivilege -u "guest"  
.\ntrights.exe -r SeRemoteShutdownPrivilege -u "guest"
.\ntrights.exe -r SeAuditPrivilege -u "guest"
.\ntrights.exe -r SeIncreaseWorkingSetPrivilege -u "guest"
.\ntrights.exe -r SeLoadDriverPrivilege -u "guest"
.\ntrights.exe -r SeLockMemoryPrivilege -u "guest"
.\ntrights.exe -r SeBatchLogonRight -u "guest"
.\ntrights.exe -r SeServiceLogonRight -u "guest"
.\ntrights.exe -r SeSecurityPrivilege -u "guest"
.\ntrights.exe -r SeRelabelPrivilege -u "guest"
.\ntrights.exe -r SeSystemEnvironmentPrivilege -u "guest"
.\ntrights.exe -r SeProfileSingleProcessPrivilege -u "guest"
.\ntrights.exe -r SeSystemProfilePrivilege -u "guest"
.\ntrights.exe -r SeUndockPrivilege -u "guest"
.\ntrights.exe -r SeAssignPrimaryTokenPrivilege -u "guest"
.\ntrights.exe -r SeRestorePrivilege -u "guest"
.\ntrights.exe -r SeShutdownPrivilege -u "guest"
.\ntrights.exe -r SeSyncAgentPrivilege -u "guest"
.\ntrights.exe -r SeTakeOwnershipPrivilege -u "guest"
.\ntrights.exe -r SeCreatePermanentPrivilege -u "guest"
.\ntrights.exe -r SeTcbPrivilege -u "guest"
.\ntrights.exe -r SeMachineAccountPrivilege -u "guest"
.\ntrights.exe -r SeLockMemoryPrivilege -u "guest"
.\ntrights.exe -r SeSecurityPrivilege -u "guest"
.\ntrights.exe -r SeSystemEnvironmentPrivilege -u "guest"
.\ntrights.exe -r SeManageVolumePrivilege -u "guest"
.\ntrights.exe -r SeProfileSingleProcessPrivilege -u "guest"
.\ntrights.exe -r SeUndockPrivilege -u "guest"
.\ntrights.exe -r SeAssignPrimaryTokenPrivilege -u "guest"
.\ntrights.exe -r SeRestorePrivilege -u "guest"
.\ntrights.exe -r SeShutdownPrivilege -u "guest"
.\ntrights.exe -r SeSyncAgentPrivilege -u "guest"
.\ntrights.exe -r SeTakeOwnershipPrivilege -u "guest" 

net user guest /active:no
net accounts /minpwlen:12
net accounts /lockoutthreshold:10
net accounts /lockoutduration:30

<#Ask client about special applications that use SMB V1#>
<#Ask client about password policies#>
<#Ask client about idle time limit for active but idle Remote Desktop Services sessions#>
<#Ask client about disconnected time limit for active but idle Remote Desktop Services sessions#>

Pause



