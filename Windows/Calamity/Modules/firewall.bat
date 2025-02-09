netsh advfirewall set allprofiles state on
netsh advfirewall reset

netsh advfirewall set domainprofile state on
netsh advfirewall set domainprofile firewallpolicy blockinbound,allowoutbound
netsh advfirewall set domainprofile logging filename %SystemRoot%\System32\logfiles\firewall\domainfw.log
netsh advfirewall set domainprofile logging maxfilesize 16384
netsh advfirewall set domainprofile logging droppedconnections enable
netsh advfirewall set domainprofile logging allowedconnections enable

netsh advfirewall set privateprofile state on
netsh advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound
netsh advfirewall set privateprofile logging filename %SystemRoot%\System32\logfiles\firewall\publicfw.log
netsh advfirewall set privateprofile logging maxfilesize 16384
netsh advfirewall set privateprofile logging droppedconnections enable
netsh advfirewall set privateprofile logging allowedconnections enable

netsh advfirewall set publicprofile state on
netsh advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound
netsh advfirewall set publicprofile logging filename %SystemRoot%\System32\logfiles\firewall\privatefw.log
netsh advfirewall set publicprofile logging maxfilesize 16384
netsh advfirewall set publicprofile logging droppedconnections enable
netsh advfirewall set publicprofile logging allowedconnections enable

netsh advfirewall show allprofiles
netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no
netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no
netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no
netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no
netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no
netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no
netsh advfirewall firewall set rule group="remote desktop" new enable=no
netsh advfirewall firewall set rule name="Telnet Server" new enable=no
netsh advfirewall firewall set rule name="netcat" new enable=no
netsh advfirewall firewall add rule name="Block135tout" protocol=TCP dir=out remoteport=135 action=block
netsh advfirewall firewall add rule name="Block135uout" protocol=UDP dir=out remoteport=135 action=block
netsh advfirewall firewall add rule name="Block135tin" protocol=TCP dir=in localport=135 action=block
netsh advfirewall firewall add rule name="Block135tout" protocol=UDP dir=in localport=135 action=block
netsh advfirewall firewall add rule name="Block137tout" protocol=TCP dir=out remoteport=137 action=block
netsh advfirewall firewall add rule name="Block137uout" protocol=UDP dir=out remoteport=137 action=block
netsh advfirewall firewall add rule name="Block137tin" protocol=TCP dir=in localport=137 action=block
netsh advfirewall firewall add rule name="Block137tout" protocol=UDP dir=in localport=137 action=block
netsh advfirewall firewall add rule name="Block138tout" protocol=TCP dir=out remoteport=138 action=block
netsh advfirewall firewall add rule name="Block138uout" protocol=UDP dir=out remoteport=138 action=block
netsh advfirewall firewall add rule name="Block138tin" protocol=TCP dir=in localport=138 action=block
netsh advfirewall firewall add rule name="Block138tout" protocol=UDP dir=in localport=138 action=block
netsh advfirewall firewall add rule name="Block139tout" protocol=TCP dir=out remoteport=139 action=block
netsh advfirewall firewall add rule name="Block139uout" protocol=UDP dir=out remoteport=139 action=block
netsh advfirewall firewall add rule name="Block139tin" protocol=TCP dir=in localport=139 action=block
netsh advfirewall firewall add rule name="Block139tout" protocol=UDP dir=in localport=139 action=block

:: Disable default rules.
netsh advfirewall firewall set rule group="Connect" new enable=no
netsh advfirewall firewall set rule group="Contact Support" new enable=no
netsh advfirewall firewall set rule group="Cortana" new enable=no
netsh advfirewall firewall set rule group="DiagTrack" new enable=no
netsh advfirewall firewall set rule group="Feedback Hub" new enable=no
netsh advfirewall firewall set rule group="Microsoft Photos" new enable=no
netsh advfirewall firewall set rule group="OneNote" new enable=no
netsh advfirewall firewall set rule group="Remote Assistance" new enable=no
netsh advfirewall firewall set rule group="Windows Spotlight" new enable=no

:: Delete custom rules in case script has previously run.
netsh advfirewall firewall delete rule name="block_Connect_in"
netsh advfirewall firewall delete rule name="block_Connect_out"
netsh advfirewall firewall delete rule name="block_ContactSupport_in"
netsh advfirewall firewall delete rule name="block_ContactSupport_out"
netsh advfirewall firewall delete rule name="block_Cortana_in"
netsh advfirewall firewall delete rule name="block_Cortana_out"
netsh advfirewall firewall delete rule name="block_DiagTrack_in"
netsh advfirewall firewall delete rule name="block_DiagTrack_out"
netsh advfirewall firewall delete rule name="block_dmwappushservice_in"
netsh advfirewall firewall delete rule name="block_dmwappushservice_out"
netsh advfirewall firewall delete rule name="block_FeedbackHub_in"
netsh advfirewall firewall delete rule name="block_FeedbackHub_out"
netsh advfirewall firewall delete rule name="block_OneNote_in"
netsh advfirewall firewall delete rule name="block_OneNote_out"
netsh advfirewall firewall delete rule name="block_Photos_in"
netsh advfirewall firewall delete rule name="block_Photos_out"
netsh advfirewall firewall delete rule name="block_RemoteRegistry_in"
netsh advfirewall firewall delete rule name="block_RemoteRegistry_out"
netsh advfirewall firewall delete rule name="block_RetailDemo_in"
netsh advfirewall firewall delete rule name="block_RetailDemo_out"
netsh advfirewall firewall delete rule name="block_WMPNetworkSvc_in"
netsh advfirewall firewall delete rule name="block_WMPNetworkSvc_out"
netsh advfirewall firewall delete rule name="block_WSearch_in"
netsh advfirewall firewall delete rule name="block_WSearch_out"

:: Add custom blocking rules.
netsh advfirewall firewall add rule name="block_Connect_in" dir=in program="%WINDIR%\SystemApps\Microsoft.PPIProjection_cw5n1h2txyewy\Receiver.exe" action=block enable=yes
netsh advfirewall firewall add rule name="block_Connect_out" dir=out program="%WINDIR%\SystemApps\Microsoft.PPIProjection_cw5n1h2txyewy\Receiver.exe" action=block enable=yes
netsh advfirewall firewall add rule name="block_ContactSupport_in" dir=in program="%WINDIR%\SystemApps\ContactSupport_cw5n1h2txyewy\ContactSupport.exe" action=block enable=yes
netsh advfirewall firewall add rule name="block_ContactSupport_out" dir=out program="%WINDIR%\SystemApps\ContactSupport_cw5n1h2txyewy\ContactSupport.exe" action=block enable=yes
netsh advfirewall firewall add rule name="block_Cortana_in" dir=in program="%WINDIR%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" action=block enable=yes
netsh advfirewall firewall add rule name="block_Cortana_out" dir=out program="%WINDIR%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" action=block enable=yes
netsh advfirewall firewall add rule name="block_DiagTrack_in" dir=in service="DiagTrack" action=block enable=yes
netsh advfirewall firewall add rule name="block_DiagTrack_out" dir=out service="DiagTrack" action=block enable=yes
netsh advfirewall firewall add rule name="block_dmwappushservice_in" dir=in service="dmwappushservice" action=block enable=yes
netsh advfirewall firewall add rule name="block_dmwappushservice_out" dir=out service="dmwappushservice" action=block enable=yes
netsh advfirewall firewall add rule name="block_FeedbackHub_in" dir=in program="%ProgramFiles%\WindowsApps\Microsoft.WindowsFeedbackHub_1.1708.2831.0_x64__8wekyb3d8bbwe\PilotshubApp.exe" action=block enable=yes
netsh advfirewall firewall add rule name="block_FeedbackHub_out" dir=out program="%ProgramFiles%\WindowsApps\Microsoft.WindowsFeedbackHub_1.1708.2831.0_x64__8wekyb3d8bbwe\PilotshubApp.exe" action=block enable=yes
netsh advfirewall firewall add rule name="block_OneNote_in" dir=in program="%ProgramFiles%\WindowsApps\Microsoft.Office.OneNote_17.8625.21151.0_x64__8wekyb3d8bbwe\onenoteim.exe" action=block enable=yes
netsh advfirewall firewall add rule name="block_OneNote_out" dir=out program="%ProgramFiles%\WindowsApps\Microsoft.Office.OneNote_17.8625.21151.0_x64__8wekyb3d8bbwe\onenoteim.exe" action=block enable=yes
netsh advfirewall firewall add rule name="block_Photos_in" dir=in program="%ProgramFiles%\WindowsApps\Microsoft.Windows.Photos_2017.39091.16340.0_x64__8wekyb3d8bbwe\Microsoft.Photos.exe" action=block enable=yes
netsh advfirewall firewall add rule name="block_Photos_out" dir=out program="%ProgramFiles%\WindowsApps\Microsoft.Windows.Photos_2017.39091.16340.0_x64__8wekyb3d8bbwe\Microsoft.Photos.exe" action=block enable=yes
netsh advfirewall firewall add rule name="block_RemoteRegistry_in" dir=in service="RemoteRegistry" action=block enable=yes
netsh advfirewall firewall add rule name="block_RemoteRegistry_out" dir=out service="RemoteRegistry" action=block enable=yes
netsh advfirewall firewall add rule name="block_RetailDemo_in" dir=in service="RetailDemo" action=block enable=yes
netsh advfirewall firewall add rule name="block_RetailDemo_out" dir=out service="RetailDemo" action=block enable=yes
netsh advfirewall firewall add rule name="block_WMPNetworkSvc_in" dir=in service="WMPNetworkSvc" action=block enable=yes
netsh advfirewall firewall add rule name="block_WMPNetworkSvc_out" dir=out service="WMPNetworkSvc" action=block enable=yes
netsh advfirewall firewall add rule name="block_WSearch_in" dir=in service="WSearch" action=block enable=yes
netsh advfirewall firewall add rule name="block_WSearch_out" dir=out service="WSearch" action=block enable=yes