:: Operating System (thank you to, Compo [user:6738015], user on stackoverflow)
Set "_P="
For /F "EOL=P Tokens=*" %%A In ('"WMIC OS Get ProductType,Version 2>Nul"'
) Do For /F "Tokens=1-3 Delims=. " %%B In ("%%A") Do Set /A _P=%%B,_V=%%C%%D
If Not Defined _P Exit /B
If %_V% Lss 62 Exit /B
If %_P% Equ 1 (If %_V% Equ 62 Set "OS=Windows8"
    If %_V% Equ 63 Set "OS=Windows81"
    If %_V% Equ 100 Set "OS=Windows10"
) Else If %_V% Equ 100 (Set "OS=Server2016") Else Exit /B
Set OS

if "%OS%" EQU "Windows10" set Operating=true
if "%OS%" EQU "Windows81" set Operating=true
if "%OS%" EQU "Windows8" set Operating=true
if "%OS%" EQU "Server2016" set Operating=false
if /I "%Operating%" EQU "false" goto Server
  :: Windows 10 and Windows 8.1 and Windows8
  "%~dp0..\Executables\LGPO.exe" /m "%~dp0..\Perfect\DomainSysvol\GPO\Machine\registry.pol"
  "%~dp0..\Executables\LGPO.exe" /u "%~dp0..\Perfect\DomainSysvol\GPO\User\registry.pol"
  "%~dp0..\Executables\LGPO.exe" /s "%~dp0..\Perfect\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"
  "%~dp0..\Executables\LGPO.exe" /ac "%~dp0..\Perfect\DomainSysvol\GPO\Machine\microsoft\windows nt\Audit\audit.csv"
  reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /V DisableExceptionChainValidation /T REG_DWORD /D 0 /F
  reg add HKLM\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowSignInOptions /V value /T REG_DWORD /D 0 /F
  reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config /V DownloadMode /T REG_DWORD /D 0 /F
  reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config /V DODownloadMode /T REG_DWORD /D 0 /F

  :: They kept changing the value name for this, so I'm just doing all of them.
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /V AllowCortana /T REG_DWORD /D 0 /F
  reg add HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config /V AutoConnectAllowedOEM /T REG_DWORD /D 0 /F
  reg add HKLM\Software\Policies\Microsoft\Windows\OneDrive /V DisableFileSyncNGSC /T REG_DWORD /D 1 /F
  reg add HKLM\Software\Policies\Microsoft\Windows\OneDrive /V DisableFileSync /T REG_DWORD /D 1 /F

goto AfterServerPol

:Server
  :: Windows Server
  "%~dp0..\Executables\LGPO.exe" /m "%~dp0..\Perfect\ServerDomainSysvol\GPO\Machine\registry.pol"
  "%~dp0..\Executables\LGPO.exe" /u "%~dp0..\Perfect\ServerDomainSysvol\GPO\User\registry.pol"
  "%~dp0..\Executables\LGPO.exe" /s "%~dp0..\Perfect\ServerDomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf"
  "%~dp0..\Executables\LGPO.exe" /ac "%~dp0..\Perfect\ServerDomainSysvol\GPO\Machine\microsoft\windows nt\Audit\audit.csv"

:AfterServerPol