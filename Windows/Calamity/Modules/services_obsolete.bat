dism /online /disable-feature /featurename:IIS-WebServerRole /NoRestart
dism /online /disable-feature /featurename:IIS-WebServer /NoRestart
dism /online /disable-feature /featurename:IIS-CommonHttpFeatures /NoRestart
dism /online /disable-feature /featurename:IIS-HttpErrors /NoRestart
dism /online /disable-feature /featurename:IIS-HttpRedirect /NoRestart
dism /online /disable-feature /featurename:IIS-ApplicationDevelopment /NoRestart
dism /online /disable-feature /featurename:IIS-NetFxExtensibility /NoRestart
dism /online /disable-feature /featurename:IIS-NetFxExtensibility45 /NoRestart
dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics /NoRestart
dism /online /disable-feature /featurename:IIS-HttpLogging /NoRestart
dism /online /disable-feature /featurename:IIS-LoggingLibraries /NoRestart
dism /online /disable-feature /featurename:IIS-RequestMonitor /NoRestart
dism /online /disable-feature /featurename:IIS-HttpTracing /NoRestart
dism /online /disable-feature /featurename:IIS-Security /NoRestart
dism /online /disable-feature /featurename:IIS-URLAuthorization /NoRestart
dism /online /disable-feature /featurename:IIS-RequestFiltering /NoRestart
dism /online /disable-feature /featurename:IIS-IPSecurity /NoRestart
dism /online /disable-feature /featurename:IIS-Performance /NoRestart
dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic /NoRestart
dism /online /disable-feature /featurename:IIS-WebServerManagementTools /NoRestart
dism /online /disable-feature /featurename:IIS-ManagementScriptingTools /NoRestart
dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility /NoRestart
dism /online /disable-feature /featurename:IIS-Metabase /NoRestart
dism /online /disable-feature /featurename:IIS-HostableWebCore /NoRestart
dism /online /disable-feature /featurename:IIS-StaticContent /NoRestart
dism /online /disable-feature /featurename:IIS-DefaultDocument /NoRestart
dism /online /disable-feature /featurename:IIS-DirectoryBrowsing /NoRestart
dism /online /disable-feature /featurename:IIS-WebDAV /NoRestart
dism /online /disable-feature /featurename:IIS-WebSockets /NoRestart
dism /online /disable-feature /featurename:IIS-ApplicationInit /NoRestart
dism /online /disable-feature /featurename:IIS-ASPNET /NoRestart
dism /online /disable-feature /featurename:IIS-ASPNET45 /NoRestart
dism /online /disable-feature /featurename:IIS-ASP /NoRestart
dism /online /disable-feature /featurename:IIS-CGI /NoRestart
dism /online /disable-feature /featurename:IIS-ISAPIExtensions /NoRestart
dism /online /disable-feature /featurename:IIS-ISAPIFilter /NoRestart
dism /online /disable-feature /featurename:IIS-ServerSideIncludes /NoRestart
dism /online /disable-feature /featurename:IIS-CustomLogging /NoRestart
dism /online /disable-feature /featurename:IIS-BasicAuthentication /NoRestart
dism /online /disable-feature /featurename:IIS-HttpCompressionStatic /NoRestart
dism /online /disable-feature /featurename:IIS-ManagementConsole /NoRestart
dism /online /disable-feature /featurename:IIS-ManagementService /NoRestart
dism /online /disable-feature /featurename:IIS-WMICompatibility /NoRestart
dism /online /disable-feature /featurename:IIS-LegacyScripts /NoRestart
dism /online /disable-feature /featurename:IIS-LegacySnapIn /NoRestart
dism /online /disable-feature /featurename:IIS-FTPServer /NoRestart
dism /online /disable-feature /featurename:IIS-FTPSvc /NoRestart
dism /online /disable-feature /featurename:IIS-FTPExtensibility /NoRestart
dism /online /disable-feature /featurename:TFTP /NoRestart
dism /online /disable-feature /featurename:TelnetClient /NoRestart
dism /online /disable-feature /featurename:TelnetServer /NoRestart
Dism /Quite /Online /Disable-Feature /FeatureName:WindowsPowerShellWebAccess > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RemoteAccessMgmtTools > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RemoteAccessPowerShell > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:RemoteAccess > NUL
Dism /Quite /Online /Disable-Feature /FeatureName:Remote-Desktop-Services > NUL

:: Privacy - Stop unneeded services.
net stop DiagTrack
net stop dmwappushservice
net stop RemoteRegistry
net stop RetailDemo
net stop WinRM
net stop WMPNetworkSvc

:: Privacy - Delete, or disable, unneeded services.
sc config RemoteRegistry start=disabled
sc config RetailDemo start=disabled
sc config WinRM start=disabled
sc config WMPNetworkSvc start=disabled
sc delete DiagTrack
sc delete dmwappushservice

echo Done with SERVICES/Features simple

cls
echo. & echo Configuring services advanced

:: Services that should be burned at the stake.
for %%S in (tapisrv,bthserv,mcx2svc,remoteregistry,seclogon,telnet,tlntsvr,p2pimsvc,simptcp,fax,msftpsvc,nettcpportsharing,iphlpsvc,lfsvc,bthhfsrv,irmon,sharedaccess,xblauthmanager,xblgamesave,xboxnetapisvc) do (
	sc config %%S start= disabled
	sc stop %%S
)

:: Services that are an automatic start.
for %%S in (eventlog,mpssvc) do (
	sc config %%S start= auto
	sc start %%S
)

:: Services that are an automatic (delayed) start.
for %%S in (windefend,sppsvc,wuauserv) do (
	sc config %%S start= delayed-auto
	sc start %%S
)

:: Services that are a manual start.
for %%S in (wersvc,wecsvc) do (
	sc config %%S start= demand
)