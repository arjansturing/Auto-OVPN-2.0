#Requires -RunAsAdministrator

<#
Auto-OVPN.ps1

Version 2.0

By: Arjan Sturing

Powershell Script for:

- Automated installation OpenVPN & Power-RSA
- Automated creation of PKI & Server config.
- Automated creation of Client base config.
- Adding routes to Server config.
- Adding DNS server to Server config.
- Adding lookup domain to Server config.
- Automated creation of password protected client and config.

Automate the world! #PowerShell

#>

# Script Banner
Function Banner {
Write-Host "_______       _____            __________    ______________   __" -ForegroundColor Red
Write-Host "___    |___  ___  /______      __  __ \_ |  / /__  __ \__  | / /" -ForegroundColor Red
Write-Host "__  /| |  / / /  __/  __ \     _  / / /_ | / /__  /_/ /_   |/ / " -ForegroundColor Red
Write-Host "_  ___ / /_/ // /_ / /_/ /     / /_/ /__ |/ / _  ____/_  /|  /  " -ForegroundColor Red
Write-Host "/_/  |_\__,_/ \__/ \____/      \____/ _____/  /_/     /_/ |_/   " -ForegroundColor Red
Write-Host ""
Write-Host "By: Arjan Sturing" -ForeGroundColor Green
Write-Host ""
Write-Host "Automate the world! #PowerShell" -ForegroundColor Yellow
Write-Host ""
}

# Function for downloading and installing OpenVPN and PowerRSA
Function InstallOVPN {
$answer = Read-Host "Type: FRESH if you want to uninstall current OpenVPN installations including the configuration before installing OpenVPN"
if ($answer -eq "FRESH"){
UninstallOVPN
cls
Banner}
Else
{cls
Banner}
$desktopdir = [Environment]::GetFolderPath("Desktop")
$OVPN25 = "https://swupdate.openvpn.org/community/releases/OpenVPN-2.5.0-I601-amd64.msi"
$PowerRSA = "https://github.com/arjansturing/Power-RSA-2.0/archive/main.zip"
$TempDir = "C:\OVPN-TEMPDIR"
Write-Host "Installing OpenVPN....." -ForegroundColor Green
md $TempDir -Force
Invoke-WebRequest -Uri $OVPN25 -OutFile "$TempDir\OVPN.msi"
Invoke-WebRequest -Uri $PowerRSA -OutFile "$TempDir\PowerRsa.zip"
Expand-Archive -Path $TempDir\PowerRsa.zip -DestinationPath $TempDir -Force
cd $TempDir
Start-Process -FilePath msiexec.exe -Wait -ArgumentList '/I OVPN.msi /qn ADDLOCAL=ALL'
$ovpndir=(New-Object -ComObject WScript.Shell).RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\OpenVPN\") | %{$_.Substring(0, $_.length - 1) }
$powerrsadir="$ovpndir\powerrsa"
md $powerrsadir -Force
Copy-Item -Path $TempDir\Power-RSA-2.0-main\* -Destination $powerrsadir -Recurse
cd c:\
Remove-Item -LiteralPath $TempDir -Force -Recurse

# Disable IPV6 on TAP adapter
Get-NetAdapter | Where InterfaceDescription -like "*TAP*" | Disable-NetAdapterBinding -ComponentID ms_tcpip6

# Create PowerRSA desktop icon
$TargetFile = "powershell.exe"
$Arguments = ('-noexit -ExecutionPolicy Bypass -File "'+($powerrsadir)+('\power-rsa.ps1')+('"'))
$ShortcutFile = "$desktopdir\OpenVPN-PowerRSA.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
$Shortcut.IconLocation = "shell32.dll, 76"
$Shortcut.TargetPath = $TargetFile
$Shortcut.Arguments = $Arguments
$Shortcut.Save()
}

# Function for creating PKI, Server Config and default client config
Function configserver {

$env:ovpndir=(New-Object -ComObject WScript.Shell).RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\OpenVPN\") | %{$_.Substring(0, $_.length - 1) }
$env:powerrsadir="$env:ovpndir\powerrsa"
$ServerConfigFile="$env:ovpndir\config\server.ovpn"
$currentip = (Get-NetIPAddress | Where-Object {$_.AddressState -eq "Preferred" -and $_.ValidLifetime -lt "24:00:00"}).IPAddress
$LocalIP=Read-Host "Enter local IP of OpenVPN Server (Default is $currentip)"
if ($LocalIP -eq [string]::empty){
$LocalIP = $currentip
}
Else
{}
$Port=Read-Host "Enter desired port of OpenVPN Server (Default is 1194)"
if ($Port -eq [string]::empty){
$Port = "1194"
}
Else
{}

# Create Server Config File
Remove-Item $ServerConfigFile -Force -ErrorAction SilentlyContinue
New-Item $ServerConfigFile -Force -ErrorAction SilentlyContinue
Add-Content $ServerConfigFile "local $LocalIP" -Force -ErrorAction SilentlyContinue
Add-Content $ServerConfigFile "port $Port" -Force -ErrorAction SilentlyContinue
Add-Content $ServerConfigFile "proto udp4" -Force -ErrorAction SilentlyContinue
Add-Content $ServerConfigFile "dev tun" -Force -ErrorAction SilentlyContinue
Add-Content $ServerConfigFile "topology subnet" -Force -ErrorAction SilentlyContinue
Add-Content $ServerConfigFile "mode server" -Force -ErrorAction SilentlyContinue
Add-Content $ServerConfigFile "tls-server" -Force -ErrorAction SilentlyContinue
Add-Content $ServerConfigFile "server 10.8.0.0 255.255.255.0" -Force -ErrorAction SilentlyContinue
Add-Content $ServerConfigFile "keepalive 10 120" -Force -ErrorAction SilentlyContinue
Add-Content $ServerConfigFile "cipher AES-256-GCM" -Force -ErrorAction SilentlyContinue
Add-Content $ServerConfigFile "key-direction 0" -Force -ErrorAction SilentlyContinue
Add-Content $ServerConfigFile "persist-key" -Force -ErrorAction SilentlyContinue
Add-Content $ServerConfigFile "persist-tun" -Force -ErrorAction SilentlyContinue
Add-Content $ServerConfigFile "verb 3" -Force -ErrorAction SilentlyContinue
Add-Content $ServerConfigFile "mute 20" -Force -ErrorAction SilentlyContinue
Add-Content $ServerConfigFile "explicit-exit-notify 1" -Force -ErrorAction SilentlyContinue

# Init PKI
Remove-Item $env:powerrsadir\pki -Force -Recurse -ErrorAction SilentlyContinue
md $env:powerrsadir -Force -ErrorAction SilentlyContinue
md "$env:powerrsadir\pki" -Force -ErrorAction SilentlyContinue
New-Item $env:powerrsadir\variables.ps1 -Force -ErrorAction SilentlyContinue
New-Item $env:powerrsadir\pki\index.txt -Force -ErrorAction SilentlyContinue
New-Item $env:powerrsadir\pki\serial -Force -ErrorAction SilentlyContinue
Add-Content $env:powerrsadir\pki\serial "01" -Force -ErrorAction SilentlyContinue
$OVPNDIR=$env:ovpndir
cls
Write-Host ""
Write-Host "PKI init started..." -ForegroundColor Green
Write-Host ""
$COUNTRY=Read-Host "Enter Country"
$PROVINCE= Read-Host "Enter State of Province"
$CITY=Read-Host "Enter City"
$ORG=Read-Host "Enter Organization Name"
$EMAIL=Read-Host "Enter E-Mail Address"
$OU=Read-Host "Enter Department Name"
Add-Content $env:powerrsadir\variables.ps1 ('$env:ovpndir="'+($OVPNDIR)+('"')) -Force -ErrorAction SilentlyContinue
Add-Content $env:powerrsadir\variables.ps1  '$env:powerrsadir="$env:ovpndir\powerrsa"' -Force -ErrorAction SilentlyContinue
Add-Content $env:powerrsadir\variables.ps1  '$env:PATH="$env:ovpndir\bin"' -Force -ErrorAction SilentlyContinue
Add-Content $env:powerrsadir\variables.ps1  '$env:HOME=$env:powerrsadir' -Force -ErrorAction SilentlyContinue
Add-Content $env:powerrsadir\variables.ps1  '$env:KEY_CONFIG="$env:powerrsadir\config\openssl-powerrsa.cnf"' -Force -ErrorAction SilentlyContinue
Add-Content $env:powerrsadir\variables.ps1  '$env:KEY_DIR="pki"'-Force -ErrorAction SilentlyContinue
Add-Content $env:powerrsadir\variables.ps1  '$env:DH_KEY_SIZE="2048"' -Force -ErrorAction SilentlyContinue
Add-Content $env:powerrsadir\variables.ps1  '$env:KEY_SIZE="4096"' -Force -ErrorAction SilentlyContinue
Add-Content $env:powerrsadir\variables.ps1  ('$env:KEY_COUNTRY="'+($COUNTRY)+('"')) -Force -ErrorAction SilentlyContinue
Add-Content $env:powerrsadir\variables.ps1  ('$env:KEY_PROVINCE="'+($PROVINCE)+('"'))-Force -ErrorAction SilentlyContinue
Add-Content $env:powerrsadir\variables.ps1  ('$env:KEY_CITY="'+($CITY)+('"')) -Force -ErrorAction SilentlyContinue
Add-Content $env:powerrsadir\variables.ps1  ('$env:KEY_ORG="'+($ORG)+('"')) -Force -ErrorAction SilentlyContinue
Add-Content $env:powerrsadir\variables.ps1  ('$env:KEY_EMAIL="'+($EMAIL)+('"')) -Force -ErrorAction SilentlyContinue
Add-Content $env:powerrsadir\variables.ps1  ('$env:KEY_OU="'+($OU)+('"')) -Force -ErrorAction SilentlyContinue
Add-Content $env:powerrsadir\variables.ps1  '$env:PKCS11_MODULE_PATH="changeme"' -Force -ErrorAction SilentlyContinue
Add-Content $env:powerrsadir\variables.ps1  '$env:PKCS11_PIN="1234"' -Force -ErrorAction SilentlyContinue
cd $env:powerrsadir
. .\variables.ps1
cls


# Create CA
$env:KEY_CN="ca"
$env:KEY_NAME=$env:KEY_CN
openssl req -days 3650 -nodes -new -x509 -keyout $env:KEY_DIR\ca.key -out $env:KEY_DIR\ca.crt -config $env:KEY_CONFIG -batch 
Add-Content -path "$ServerConfigFile" "<ca>"
Get-Content -path "$env:KEY_DIR\ca.crt" | Add-Content -path "$ServerConfigFile"
Add-Content -path "$ServerConfigFile" "</ca>"
cls


# Create Server certificate
$keyname = Read-Host "Enter Servername (Default is: Server)"
if ($keyname -eq [string]::empty){
$keyname = "Server"
}
Else
{}
$env:KEY_CN = $keyname
$env:KEY_NAME = $env:KEY_CN
cd $env:HOME
openssl req -days 3650 -nodes -new -keyout $env:KEY_DIR\$env:KEY_CN.key -out $env:KEY_DIR\$env:KEY_CN.csr -config $env:KEY_CONFIG -batch
openssl ca -days 3650 -out $env:KEY_DIR\$env:KEY_CN.crt -in $env:KEY_DIR\$env:KEY_CN.csr -extensions server -config $env:KEY_CONFIG -batch
cd $env:HOME
cd $env:KEY_DIR
Get-ChildItem *.old | foreach { Remove-Item -Path $_.FullName }
cd $env:HOME
Add-Content -path "$ServerConfigFile" "<cert>"
Get-Content -path "$env:KEY_DIR\$env:KEY_CN.crt" | Add-Content -path "$ServerConfigFile"
Add-Content -path "$ServerConfigFile" "</cert>"
Add-Content -path "$ServerConfigFile" "<key>"
Get-Content -path "$env:KEY_DIR\$env:KEY_CN.key" | Add-Content -path "$ServerConfigFile"
Add-Content -path "$ServerConfigFile" "</key>"
cls

#Create DH
cd $env:HOME
openssl dhparam -out $env:KEY_DIR\DH$env:DH_KEY_SIZE.pem $env:DH_KEY_SIZE   
Add-Content -path "$ServerConfigFile" "<dh>"
Get-Content -path "$env:KEY_DIR\DH$env:DH_KEY_SIZE.pem" | Add-Content -path "$ServerConfigFile"
Add-Content -path "$ServerConfigFile" "</dh>"
cls

#Create Tls Crypt V2 Key
Banner
cd $env:HOME
openvpn --genkey tls-crypt-v2-server $env:KEY_DIR\v2crypt-server.key   
Add-Content -path "$ServerConfigFile" "<tls-crypt-v2>"
Get-Content -path "$env:KEY_DIR\v2crypt-server.key" | Add-Content -path "$ServerConfigFile"
Add-Content -path "$ServerConfigFile" "</tls-crypt-v2>"
cls

#Create Default Client Config file.
$env:CONFIG = "$env:ovpndir\client"
$env:DEFAULTCONFIG = "$env:ovpndir\client\default"
$ClientConfig = "$env:DEFAULTCONFIG\default.ovpn"
$ExternalIP = (Invoke-WebRequest -uri "http://ifconfig.me/ip" -UseBasicParsing).Content
$Remote = Read-Host "Enter external IP or FQDN of OpenVPN Server (Default is $ExternalIP)"
if ($Remote -eq [string]::empty){
$Remote = $ExternalIP
}
md $env:CONFIG -Force -ErrorAction SilentlyContinue
md $env:DEFAULTCONFIG -Force -ErrorAction SilentlyContinue

New-Item "$ClientConfig" -Force -ErrorAction SilentlyContinue
Add-Content "$ClientConfig" "client" -Force -ErrorAction SilentlyContinue
Add-Content "$ClientConfig" "dev tun" -Force -ErrorAction SilentlyContinue
Add-Content "$ClientConfig" "proto udp4" -Force -ErrorAction SilentlyContinue
Add-Content "$ClientConfig" "remote $Remote $Port" -Force -ErrorAction SilentlyContinue
Add-Content "$ClientConfig" "resolv-retry infinite" -Force -ErrorAction SilentlyContinue
Add-Content "$ClientConfig" "nobind" -Force -ErrorAction SilentlyContinue
Add-Content "$ClientConfig" "persist-key" -Force -ErrorAction SilentlyContinue
Add-Content "$ClientConfig" "persist-tun" -Force -ErrorAction SilentlyContinue
Add-Content "$ClientConfig" "mute-replay-warnings" -Force -ErrorAction SilentlyContinue
Add-Content "$ClientConfig" "remote-cert-tls server" -Force -ErrorAction SilentlyContinue
Add-Content "$ClientConfig" "cipher AES-256-GCM" -Force -ErrorAction SilentlyContinue
Add-Content "$ClientConfig" "auth-nocache" -Force -ErrorAction SilentlyContinue
Add-Content "$ClientConfig" "key-direction 1" -Force -ErrorAction SilentlyContinue
Add-Content "$ClientConfig" "verb 3" -Force -ErrorAction SilentlyContinue
Add-Content "$ClientConfig" "mute 20" -Force -ErrorAction SilentlyContinue
Add-Content -path "$ClientConfig" "<ca>"
Get-Content -path "$ovpndir\powerrsa\pki\ca.crt" | Add-Content -path "$ClientConfig"
Add-Content -path "$ClientConfig" "</ca>"

# Set WIndows Firewall Rule
New-NetFirewallRule -DisplayName "Allow OpenVPN UDP IN" -Direction Inbound -LocalPort $Port -Protocol UDP -Action Allow -Profile Any -ErrorAction SilentlyContinue

# Setup Services
Set-Service -Name OpenVPNServiceInteractive -StartupType Disabled
Stop-Service -Name OpenVPNServiceInteractive

Set-Service -Name OpenVPNService -StartupType Automatic
Start-Service -Name OpenVPNService
cls
Write-Host "OpenVPN Server configuration is successfull!" -ForegroundColor Green
Write-Host "Inbound Windows Firewall Rule is created" -ForegroundColor Green
Write-Host "Make sure you create a port forwarding rule to $LocalIP on port $Port (UDP)" -ForegroundColor Green
Start-Sleep 15
}

# Function for adding routes
Function AddRoute {
Set-Itemproperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'IPEnableRouter' -value '1' -Force
$ovpndir=(New-Object -ComObject WScript.Shell).RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\OpenVPN\") | %{$_.Substring(0, $_.length - 1) }
$ServerConfigFile="$ovpndir\config\server.ovpn"
$ServerConfig = Get-Content -Path $ServerConfigFile
$network = Read-Host "Enter network: (example: 192.168.0.0)"
if ($network -eq [string]::empty){
Write-Host "No input, returning to main menu" -ForegroundColor Red
Start-Sleep 5
return}
Else
{}
$subnetmask = Read-Host "Enter Subnetmask (example: 255.255.255.0)"
if ($subnetmask -eq [string]::empty){
Write-Host "No input, returning to main menu" -ForegroundColor Red
Start-Sleep 5
return}
Else
{}
Add-Content $ServerConfigFile ('push'+(' ')+('"')+('route')+(' ')+($network)+(' ')+($subnetmask)+('"')) -Force -ErrorAction SilentlyContinue
Set-Service -Name RemoteAccess -StartupType Automatic
Start-Service -Name RemoteAccess

Stop-Service -Name OpenVPNService
Start-Service -Name OpenVPNService

cls
Write-Host "Routing is configured, restart the OpenVPN server to apply the changes" -ForegroundColor Green
Write-Host ""
Write-Host "Do not forget to add the following routing rule in the router:" -ForegroundColor Red
Write-Host "From: OpenVPN Range --> To: $network $subnetmask --> Gateway: Internal IP Address of OpenVPN server" -ForegroundColor Red
Start-Sleep 10
}

# Function for adding DNS server
Function AddDNS {
$env:ovpndir=(New-Object -ComObject WScript.Shell).RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\OpenVPN\") | %{$_.Substring(0, $_.length - 1) }
$ServerConfigFile="$env:ovpndir\config\server.ovpn"
$dnsserver = Read-Host "Enter IP Address of dns server"
if ($dnsserver -eq [string]::empty){
Write-Host "No input, returning to main menu" -ForegroundColor Red
Start-Sleep 5
return}
Else
{}
Add-Content $ServerConfigFile ("push"+(" ")+('"')+("dhcp-option")+(" ")+ ("DNS")+(" ")+("$dnsserver")+('"')) -Force -ErrorAction SilentlyContinue
Stop-Service -Name OpenVPNService
Start-Service -Name OpenVPNService
}

# Function for adding Lookup Domain
Function AddDomain {
$env:ovpndir=(New-Object -ComObject WScript.Shell).RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\OpenVPN\") | %{$_.Substring(0, $_.length - 1) }
$ServerConfigFile="$env:ovpndir\config\server.ovpn"
$domain = Read-Host "Enter lookup domain name"
if ($domain -eq [string]::empty){
Write-Host "No input, returning to main menu" -ForegroundColor Red
Start-Sleep 5
return}
Else
{}
Add-Content $ServerConfigFile ("push"+(" ")+('"')+("dhcp-option")+(" ")+ ("DOMAIN")+(" ")+("$domain")+('"')) -Force -ErrorAction SilentlyContinue
Stop-Service -Name OpenVPNService
Start-Service -Name OpenVPNService
}

# Create Password Protected Client Config
Function CreatePWDClientConfig
{
$env:ovpndir=(New-Object -ComObject WScript.Shell).RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\OpenVPN\") | %{$_.Substring(0, $_.length - 1) }
$env:CONFIG = "$env:ovpndir\client"
$env:DEFAULTCONFIG = "$env:ovpndir\client\default"
$ClientConfig = "$env:DEFAULTCONFIG\default.ovpn"
$keyname = Read-Host "Enter Username"
$env:KEY_CN = $keyname
$env:KEY_NAME = $env:KEY_CN
if ($keyname -eq [string]::empty){
Write-Host "No input, returning to main menu" -ForegroundColor Red
Start-Sleep 5
return}
Else
{}
cd $env:ovpndir\powerrsa
. .\variables.ps1
cd $env:HOME

cd $env:HOME
openssl req -days 3650 -new -keyout $env:KEY_DIR\$env:KEY_CN.key -out $env:KEY_DIR\$env:KEY_CN.csr -config $env:KEY_CONFIG -batch
openssl ca -days 3650 -out $env:KEY_DIR\$env:KEY_CN.crt -in $env:KEY_DIR\$env:KEY_CN.csr -config $env:KEY_CONFIG -batch
cd $env:HOME
cd $env:KEY_DIR
Get-ChildItem *.old | foreach { Remove-Item -Path $_.FullName }
openvpn --tls-crypt-v2 $env:HOME\$env:KEY_DIR\v2crypt-server.key --genkey tls-crypt-v2-client $env:HOME\$env:KEY_DIR\"$env:KEY_CN"-auth.key
cd $env:CONFIG
md $env:CONFIG\$env:KEY_CN -Force -ErrorAction SilentlyContinue
Copy-Item "$ClientConfig" "$env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn" -Force -ErrorAction SilentlyContinue

Add-Content -path "$env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn" "<cert>"
Get-Content -path "$env:ovpndir\powerrsa\pki\$env:KEY_CN.crt" | Add-Content -path "$env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn"
Add-Content -path "$env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn" "</cert>"
Add-Content -path "$env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn" "<key>"
Get-Content -path "$env:ovpndir\powerrsa\pki\$env:KEY_CN.key" | Add-Content -path "$env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn"
Add-Content -path "$env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn" "</key>" 
Add-Content -path "$env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn" "<tls-crypt-v2>"
Get-Content -path $env:HOME\$env:KEY_DIR\"$keyname"-auth.key | Add-Content -path "$env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn"
Add-Content -path "$env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn" "</tls-crypt-v2>" 
cls
Write-Host "Client Config is created." -ForegroundColor Green
Write-Host "" -ForegroundColor Green
Write-Host "The location of the config file is: $env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn" -ForegroundColor Green
Start-Sleep 5
}

# Create Passwordless Client Config
Function CreateClientConfig
{
$env:ovpndir=(New-Object -ComObject WScript.Shell).RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\OpenVPN\") | %{$_.Substring(0, $_.length - 1) }
$env:CONFIG = "$env:ovpndir\client"
$env:DEFAULTCONFIG = "$env:ovpndir\client\default"
$ClientConfig = "$env:DEFAULTCONFIG\default.ovpn"
$keyname = Read-Host "Enter Username"
$env:KEY_CN = $keyname
$env:KEY_NAME = $env:KEY_CN
if ($keyname -eq [string]::empty){
Write-Host "No input, returning to main menu" -ForegroundColor Red
Start-Sleep 5
return}
Else
{}
cd $env:ovpndir\powerrsa
. .\variables.ps1

cd $env:HOME
openssl req -days 3650 -nodes -new -keyout $env:KEY_DIR\$env:KEY_CN.key -out $env:KEY_DIR\$env:KEY_CN.csr -config $env:KEY_CONFIG -batch
openssl ca -days 3650 -out $env:KEY_DIR\$env:KEY_CN.crt -in $env:KEY_DIR\$env:KEY_CN.csr -config $env:KEY_CONFIG -batch
cd $env:HOME
cd $env:KEY_DIR
Get-ChildItem *.old | foreach { Remove-Item -Path $_.FullName }
openvpn --tls-crypt-v2 $env:HOME\$env:KEY_DIR\v2crypt-server.key --genkey tls-crypt-v2-client $env:HOME\$env:KEY_DIR\"$keyname"-auth.key
cd $env:CONFIG
md $env:CONFIG\$env:KEY_CN -Force -ErrorAction SilentlyContinue
Copy-Item "$ClientConfig" "$env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn" -Force -ErrorAction SilentlyContinue

Add-Content -path "$env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn" "<cert>"
Get-Content -path "$env:ovpndir\powerrsa\pki\$env:KEY_CN.crt" | Add-Content -path "$env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn"
Add-Content -path "$env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn" "</cert>"
Add-Content -path "$env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn" "<key>"
Get-Content -path "$env:ovpndir\powerrsa\pki\$env:KEY_CN.key" | Add-Content -path "$env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn"
Add-Content -path "$env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn" "</key>" 
Add-Content -path "$env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn" "<tls-crypt-v2>"
Get-Content -path $env:HOME\$env:KEY_DIR\"$keyname"-auth.key | Add-Content -path "$env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn"
Add-Content -path "$env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn" "</tls-crypt-v2>" 
cls
Write-Host "Client Config is created." -ForegroundColor Green
Write-Host "" -ForegroundColor Green
Write-Host "The location of the config file is: $env:CONFIG\$env:KEY_CN\OVPN-CLIENT.ovpn" -ForegroundColor Green
Start-Sleep 5
}

# Function for uninstalling OpenVPN

Function UninstallOVPN {
$answer = Read-Host "Type: UNINSTALL if you want to uninstall OpenVPN including the configuration"
if ($answer -eq "UNINSTALL"){
}
Else
{
cls
Write-Host "Wrong input, returning to main menu" -ForegroundColor Red
Start-Sleep 5
return}
$desktopdir = [Environment]::GetFolderPath("Desktop")
$env:ovpndir=(New-Object -ComObject WScript.Shell).RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\OpenVPN\") | %{$_.Substring(0, $_.length - 1) }
Write-Host "Uninstalling OpenVPN....." -ForegroundColor Green
Start-Process -FilePath msiexec.exe -Wait -ArgumentList '/X {E5931AF4-2A8F-48A5-AFC8-3605AD5C0A0C} /qn'
Remove-Item $env:ovpndir -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item  "$desktopdir\OpenVPN-PowerRSA.lnk" -Force -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName "Allow OpenVPN UDP IN" -ErrorAction SilentlyContinue
}

# Function for generating CRL / Revoke certificate
Function CRL
{
$env:ovpndir=(New-Object -ComObject WScript.Shell).RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\OpenVPN\") | %{$_.Substring(0, $_.length - 1) }
$ServerConfigFile = "$env:ovpndir\config\server.ovpn"
$ServerConfig = Get-Content -Path $ServerConfigFile
cd $env:ovpndir\powerrsa
. .\variables.ps1
$keyname = Read-Host "Enter name of certificate to revoke (leave empty to generate CRL)"
if ($keyname -eq [string]::empty){
$env:KEY_CN = "TestCRLKEYDUMMY"
$env:KEY_NAME = "TestCRLKEYDUMMY"
Write-Host "No input, genertating a new CRL...." -ForegroundColor Green
Start-Sleep 2
cd $env:HOME
openssl ca -gencrl -out $env:KEY_DIR\crl.pem -config $env:KEY_CONFIG -batch
Copy-Item $env:KEY_DIR\crl.pem -Destination $env:ovpndir\config\crl.pem -Force -ErrorAction SilentlyContinue
If ($ServerConfig -imatch "crl.pem")
{}
Else {
Add-Content $ServerConfigFile "crl-verify crl.pem" -Force -ErrorAction SilentlyContinue
}
cls
Write-Host "CRL Generated!" -ForegroundColor Green
Start-Sleep 2
return}
Else
{}
$env:KEY_CN = $keyname
$env:KEY_NAME = $env:KEY_CN
cd $env:HOME
openssl ca -revoke $env:KEY_DIR\$keyname.crt -config $env:KEY_CONFIG -batch
openssl ca -gencrl -out $env:KEY_DIR\crl.pem -config $env:KEY_CONFIG -batch
Copy-Item $env:KEY_DIR\crl.pem -Destination $env:ovpndir\config\crl.pem -Force -ErrorAction SilentlyContinue
If ($ServerConfig -imatch "crl.pem")
{}
Else {
Add-Content $ServerConfigFile "crl-verify crl.pem" -Force -ErrorAction SilentlyContinue
}
cls
Write-Host "Certifitcate: $keyname is revoked!" -ForeGroundColor Green

Start-Sleep 5
Stop-Service -Name OpenVPNService
Start-Service -Name OpenVPNService
}

# Main Menu
Function MainMenu {
do {
    do {
Banner                                                                       
Write-Host "Select option:"
Write-Host ""
Write-Host "1: Install OpenVPN 2.5.0"
Write-Host "2: Create Server config & Client base config including PKI"
Write-Host "3: Enable routing and add route"
Write-Host "4: Add DNS server for DHCP clients"
Write-Host "5: Add DNS lookup domain for DHCP clients"
Write-Host "6: Create Password Protected OpenVPN User & Config"
Write-Host "7: Create Passwordless OpenVPN User & Config"
Write-Host "8: Generate CRL/Revoke Certificate"
Write-Host "U: Uninstall OpenVPN"
Write-Host "Q: Quit"
Write-Host ""
        write-host -nonewline "Enter choice and press Enter: "
        
        $choice = read-host
        
        write-host ""
        
        $ok = $choice -match '^[12345678uq]+$'
        if ( -not $ok) {
        cls 
        Write-Host "Wrong Choice!" -ForegroundColor Red
        Start-Sleep 5
        cls
        }
    } until ( $ok )
    
    switch -Regex ( $choice ) {
      
        "1"
        {
            cls
            Banner
            InstallOVPN
            cls
        }

        "2"
        {
           cls
           Banner
           configserver
           cls
        }

        "3"
        {
           cls
           Banner
           AddRoute
           cls
        }
        "4"
        {
           cls
           Banner
           AddDns
           cls
        }
        "5"
        {
           cls
           Banner
           AddDomain
           cls
          
        }
        "6"
        {
           cls
           Banner
           CreatePWDClientConfig
           cls
          
        }
        "7"
        {
           cls
           Banner
           CreateClientConfig
           cls
          
        }
        "8"
        {
           cls
           Banner
           crl
           cls
          
        }

        "u"
        {
           cls
           Banner
           UninstallOVPN
           cls
          
        }


    }
} until ( $choice -match "Q" )
} 
MainMenu
