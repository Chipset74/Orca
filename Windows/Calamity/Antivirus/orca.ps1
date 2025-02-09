Import-Module -Name ".\Helpers\malwareHelper.psm1" -Force
Import-Module -Name ".\Helpers\registryHelper.psm1" -Force
Import-Module -Name ".\Helpers\messageHelper.psm1" -Force

function startProcessUser($name) {
    $scriptPath = $PSScriptRoot + "\Modules\" + $name
    $Command = "cmd /c start powershell -NoExit -Command '& $scriptPath'"
    Start-Process -FilePath PowerShell -NoNewWindow -Credential $Credential -ArgumentList $Command
}
function startProcess($name) {
    $scriptPath = $PSScriptRoot + "\" + $name
    Invoke-Expression "cmd /c start powershell -NoExit -Command '& $scriptPath'"
}
# Global Vars

$Credential = Get-Credential 
$WindowsOS = (Get-WmiObject Win32_OperatingSystem).Caption

$commonRegistryKeys = @(
    "HKCU:\SOFTWARE\Policies\Microsoft\Windows\System\DisableCMD",
    "HKCU:\Software\Policies\Microsoft\Windows\System\DisableRegistryTools",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun",
    "HKCU:\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate\DisableWindowsUpdateAccess",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
    "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\ExcludeWUDriversInQualityUpdate"
)

# Starting Sequence
$art = @"
                             __
                         _.-~  )
              _..--~~~~,'   ,-/     _
           .-'. . . .'   ,-','    ,' )
         ,'. . . _   ,--~,-'__..-'  ,'
       ,'. . .  (@)' ---~~~~      ,'
      /. . . . '~~             ,-'
     /. . . . .             ,-'
    ; . . . .  - .        ,'
   : . . . .       _     /
  . . . . .          `-.:
 . . . ./  - .          )
.  . . |  _____..---.._/ ____ 
~---~~~~----~~~~             ~~
"@
Write-Host $art -ForegroundColor Blue
Write-Host "United we sail, divided we fail`n" -ForegroundColor Blue
Write-Host "~~~~~~~~~~~`nKey`n~~~~~~~~~~~"
Write-Host "Red | Found Threat" -ForegroundColor Red
Write-Host "Green | Information" -ForegroundColor Green
Write-Host "Dark Yellow | Category" -ForegroundColor DarkYellow

message -m "Deleting Common Annoying Registry Keys"
foreach ($key in $commonRegistryKeys) {
    Write-Host "Deleting Key: $key"
    $Command = "Remove-Item -Path $key -Force -ErrorAction SilentlyContinue"
    Start-Process -FilePath PowerShell -NoNewWindow -Credential $Credential -ArgumentList $Command
}

# Malware Checks
message -m "Checking For Malware"
winLogonHelper

messageMalware "Image File Execution Options"
ImageFileExec

messageMalware "FailureCommand"
FailureCommand

messageMalware "Security Support Provider"
SecuritySupportProvider

messageMalware "Unquoted Service Path" 
FixUnquotedServicePaths

messageMalware "AppInit DLLs"
appInitDLLs

messageMalware "Netsh Helper"
Netsh

messageMalware "BitsJobs"
bitsadmin.exe /list

messageMalware "Screensaver"
scrnsaver

messageMalware "Powershell Profiles"
powershellProfiles

messageMalware "RID Hijacking"
ridHijacking
  
# TODO - Add Check to scan every Process and its DLL, and check if its signed
# TODO - Com Hijacking

# End Malware Checks

message -m "Checking for Hidden Users"
# Win 10
Write-Host "Every User In SAM Registry"
$key = "HKLM:\SAM\SAM\Domains\Account\Users\Names"
$subkeys = Get-ChildItem -Path $key -Recurse -Force
foreach ($subkey in $subkeys) {
    if($subkey -contains "$") {
        Write-Host $subkey.PSChildName -ForegroundColor Red
    } else {
        Write-Host $subkey.PSChildName -ForegroundColor Green
    }
}

# Server
if ($WindowsOS -contains "Server") {
    Get-ADUser -Filter *
}

message -m "Checking Signed Files"
Write-Host "Starting fileTool.ps1 (dll,exe,sys,scr)"
startProcessUser -name "fileTool.ps1 -path C:\ -fileExtension dll"
startProcessUser -name "fileTool.ps1 -path C:\ -fileExtension exe"
startProcessUser -name "fileTool.ps1 -path C:\ -fileExtension sys"
startProcessUser -name "fileTool.ps1 -path C:\ -fileExtension scr"

message -m "Checking Shadow Backups"
$shadowShares = vssadmin list shadows
if ($shadowShares -contains "Contained") {
    Write-Host "Shadow Copy Detected!" -ForegroundColor Red
} 
$shadowShares

message -m "Diffing All Service Configs"
# TODO

message -m "Diffing All Dependancies"
# TODO

if ($WindowsOS -contains "Server") {
    message -m "Printing Common AD Groups"
    # TODO
    message -m "Checking AD Exploits"
    # TODO
    message -m "Securing DNS"
    startProcess -name "secureDNS.ps1"


}
