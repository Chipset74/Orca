auditpol /set /category:* /success:enable
auditpol /set /category:* /failure:enable

:: Shows all files even if Super Hidden
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /V Hidden /T REG_DWORD /D 1 /F
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /V HideFileExt /T REG_DWORD /D 0 /F
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /V ShowSuperHidden /T REG_DWORD /D 1 /F

:: Windows Update
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V AUOptions /T REG_DWORD /D 4 /F
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V ElevateNonAdmins /T REG_DWORD /D 1 /F
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V IncludeRecommendedUpdates /T REG_DWORD /D 1 /F
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V ScheduledInstallTime /T REG_DWORD /D 22 /F
sc config wuauserv start= auto
net start wuauserv

:: Netowrking/Miscellaneous
reg add "HKLM\SYSTEM\CurrentControlSet\Services\cdrom" /V AutoRun /T REG_DWORD /D 0 /F
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application" /V RestrictGuestAcess /T REG_DWORD /D 1 /F
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System" /V RestrictGuestAcess /T REG_DWORD /D 1 /F
reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security" /V RestrictGuestAcess /T REG_DWORD /D 1 /F
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /V SynAttackProtect /T REG_DWORD /D 2 /F
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /V EnableDeadGWDetect /T REG_DWORD /D 0 /F
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /V EnableICMPRedirect /T REG_DWORD /D 0 /F
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /V DisableIPSourceRouting /T REG_DWORD /D 2 /F
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /V KeepAliveTime /T REG_DWORD /D 300000 /F
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /V NoNameReleaseOnDemand /T REG_DWORD /D 1 /F
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /V TcpMaxConnectResponseRetransmissions /T REG_DWORD /D 2 /F
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /V TcpMaxDataRetransmissions /T REG_DWORD /D 3 /F
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /V TcpMaxPortsExhausted /T REG_DWORD /D 5 /F
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /V NoDriveTypeAutorun /T REG_DWORD /D 255 /F
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\Kerberos\Parameters" /V LogLevel /T REG_DWORD /D 1 /F

:: Security - Disable Autorun.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f

:: Privacy/Security - Only download Windows Updates from LAN peers, and Microsoft servers.
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d 1 /f

::Configuring UAC
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V PromptOnSecureDesktop /T REG_DWORD /D 1 /F
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V ConsentPromptBehaviorAdmin /T REG_DWORD /D 1 /F
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V ConsentPromptBehaviorUser /T REG_DWORD /D 0 /F
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V FilterAdministratorToken /T REG_DWORD /D 1 /F
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V EnableInstallerDetection /T REG_DWORD /D 1 /F
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V EnableLUA /T REG_DWORD /D 1 /F >> nul 2>&1
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V EnableVirtualization /T REG_DWORD /D 1 /F


reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V CreateEncryptedOnlyTickets /T REG_DWORD /D 1 /F
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /V fDisableEncryption /T REG_DWORD /D 0 /F
reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V fAllowFullControl /T REG_DWORD /D 0 /F
reg add "HKLM\SYSTEM\ControlSet001\Control\Remote Assistance" /V fAllowToGetHelp /T REG_DWORD /D 0 /F
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /V AllowRemoteRPC /T REG_DWORD /D 0 /F

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\HideFileExt" /v "CheckedValue" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f

del %APPDATA%\stasks.txt & del %APPDATA%\stasks2.txt

reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\Run /VA /F
reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce /VA /F
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /VA /F
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce /VA /F

dir /B "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\" >> %~dp0\..\Output\deletedfiles.txt
del /S "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*" /F /Q
dir /B "C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\" >> %~dp0\..\Output\deletedfiles.txt
del /S "C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*" /F /Q