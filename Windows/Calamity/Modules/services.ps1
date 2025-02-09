# TODO: Port services.bat to here


function Configure-IIS {
    param (
        $Enabled
    )

    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-NetFxExtensibility45" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-NetFxExtensibility" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-Performance" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-HttpCompressionDynamic" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerManagementTools" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ManagementScriptingTools" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-IIS6ManagementCompatibility" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-Metabase" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-HostableWebCore" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-DirectoryBrowsing" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebDAV" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebSockets" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ApplicationInit" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ASPNET" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-CGI" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ISAPIExtensions" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ISAPIFilter" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ServerSideIncludes" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-CustomLogging" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-BasicAuthentication" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-HttpCompressionStatic" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WMICompatibility" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-LegacyScripts" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-LegacySnapIn" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-FTPServer" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-FTPSvc" -NoRestart
    Disable-WindowsOptionalFeature -Online -FeatureName "IIS-FTPExtensibility" -NoRestart

    if ($Enabled) {
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerRole" -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServer" -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-CommonHttpFeatures" -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-HttpErrors" -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-HttpRedirect" -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-ApplicationDevelopment" -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-HealthAndDiagnostics" -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-HttpLogging" -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-LoggingLibraries" -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-RequestMonitor" -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-HttpTracing" -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-Security" -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-URLAuthorization" -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-RequestFiltering" -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-IPSecurity" -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-StaticContent" -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-DefaultDocument" -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-ManagementConsole" -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName "IIS-ManagementService" -NoRestart
    } else {
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerRole" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-WebServer" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-CommonHttpFeatures" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-HttpErrors" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-HttpRedirect" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ApplicationDevelopment" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-HealthAndDiagnostics" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-HttpLogging" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-LoggingLibraries" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-RequestMonitor" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-HttpTracing" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-Security" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-URLAuthorization" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-RequestFiltering" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-IPSecurity" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-StaticContent" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-DefaultDocument" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ManagementConsole" -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName "IIS-ManagementService" -NoRestart
    }
}

Disable-WindowsOptionalFeature -NoRestart -Online -FeatureName SMB1Protocol
Disable-WindowsOptionalFeature -NoRestart -Online -FeatureName SimpleTCP
Disable-WindowsOptionalFeature -NoRestart -Online -FeatureName TFTP
Disable-WindowsOptionalFeature -NoRestart -Online -FeatureName TelnetServer
Disable-WindowsOptionalFeature -Online -FeatureName "WindowsPowerShellWebAccess"
Disable-WindowsOptionalFeature -Online -FeatureName "RemoteAccessMgmtTools"
Disable-WindowsOptionalFeature -Online -FeatureName "RemoteAccessPowerShell"
Disable-WindowsOptionalFeature -Online -FeatureName "RemoteAccess"
Disable-WindowsOptionalFeature -Online -FeatureName "Remote-Desktop-Services"


Stop-Service -Force -Confirm -Name "DiagTrack"
Stop-Service -Force -Confirm -Name "dmwappushservice"
Stop-Service -Force -Confirm -Name "RemoteRegistry"
Stop-Service -Force -Confirm -Name "RetailDemo"
# Stop-Service -Force -Confirm -Name "WinRM"
Stop-Service -Force -Confirm -Name "WMPNetworkSvc"

Set-Service -Name "RemoteRegistry" -StartupType "Disabled"
Set-Service -Name "RetailDemo" -StartupType "Disabled"
# Set-Service -Name "WinRM" -StartupType "Disabled"
Set-Service -Name "WMPNetworkSvc" -StartupType "Disabled"
Remove-Service -Confirm -Name "DiagTrack"
Remove-Service -Confirm -Name "dmwappushservice"

$os = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption

if ($os.Caption.ToLower().Contains('windows 10')) {
    Write-Host "Current Operating System is Windows 10"
    Set-Service -Name "WinRM" -StartupType "Disabled"
    Stop-Service -Force -Confirm -Name "WinRM"
    Disable-PSRemoting
}

# Services that should be disabled
$services = "tapisrv","bthserv","mcx2svc","remoteregistry","seclogon","telnet","tlntsvr","p2pimsvc","simptcp","fax","msftpsvc","nettcpportsharing","iphlpsvc","lfsvc","bthhfsrv","irmon","sharedaccess","xblauthmanager","xblgamesave","xboxnetapisvc"
Foreach ($service in $services) {
    Set-Service -Name $service -StartupType "Disabled"
    Stop-Service -Force -Confirm -Name $service
}

# Services that should be started automatically
$services = "eventlog","mpssvc"
Foreach ($service in $services) {
    Set-Service -Name $service -StartupType "Automatic"
    Start-Service -Confirm -Name $service
}

# Services that should be started automatically (delayed)
$services = "windefend","sppsvc","wuauserv"
Foreach ($service in $services) {
    Set-Service -Name $service -StartupType "AutomaticDelayedStart"
    Start-Service -Confirm -Name $service
}

# Services that should be a manual start
$services = "wersvc","wecsvc"
Foreach ($service in $services) {
    Set-Service -Name $service -StartupType "Manual"
}

$IIS = Read-Host -Prompt "Is IIS Required? (Y/N)"
Configure-IIS -Enabled $IIS