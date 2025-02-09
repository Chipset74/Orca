#Requires -RunAsAdministrator

#region Selection Menus
function SelectionMenu() {
    Write-Host "Enter a number from the below options to run certain modules or parts"
    Write-Host "+-------------------------------------------------------------------+"
    Write-Host "| 1. Everything                                                     |"
    Write-Host "| 2. Policies                                                       |"
    Write-Host "| 3. Users                                                          |"
    Write-Host "| 4. Firewall                                                       |"
    Write-Host "| 5. Applications                                                   |"
    Write-Host "| 6. Services                                                       |"
    Write-Host "| 7. Miscellaneous                                                  |"
    Write-Host "| 8. Change Options                                                 |"
    Write-Host "| 9. Files                                                          |"
    Write-Host "| 10. Windows Defender Config                                       |"
    Write-Host "| 11. Extra Tools                                                   |"
    Write-Host "| 12. Update Apps                                                   |"
    Write-Host "| 13. Exit                                                          |"
    Write-Host "|-------------------------------------------------------------------|"
    Write-Host "| Chosen Options                                                    |"
    Write-Host "| Enable Remote Desktop: $RDP                                          |"
    Write-Host "| Enable SMB: $SMB                                                     |"
    Write-Host "| Remove Shares: $AllowShares                                                  |"
    Write-Host "| Secure Printers: $SecurePrinters (NOT DONE)                                     |"
    Write-Host "+-------------------------------------------------------------------+"            
}

function ToolsSelectionMenu() {
    Write-Host "Enter a number from the below options to run certain modules or parts"
    Write-Host "+-------------------------------------------------------------------+"
    Write-Host "| 1. Files (Prints all non-Windows Files)                           |"
    Write-Host "| 2. Print Proccesses (Prints all Running Proccesses)               |"
    Write-Host "| 3. Stig Checker                                                   |"
    Write-Host "| 4. Compare Processes                                              |"
    Write-Host "| 5. Exit                                                           |"
    Write-Host "+-------------------------------------------------------------------+"
}
#endregion

function Applications {
    Param($RDP, $SMB, $AllowShares, $SecurePrinters)
    if ($SMB -eq "N") {
        Write-Host "Removing and Disabling SMB protocols"
        Disable-WindowsOptionalFeature -NoRestart -Online -FeatureName smb1protocol
        Set-SmbServerConfiguration -Force -EnableSMB1Protocol $false
        Set-SmbServerConfiguration -Force -EnableSMB2Protocol $false
    }

    if ($RDP -eq "N") {
        Write-Host "Disabling RDP from PowerShell script"
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 1
    }

    if ($SecurePrinters -eq "Y") { 
        $scriptPath = $PSScriptRoot + "\Modules\printerSecurity.ps1"
        Invoke-Expression "cmd /c start powershell -NoExit -Command '& $scriptPath'"
    }
    $scriptPath = $PSScriptRoot + "\Modules\applications.bat $RDP $SMB $AllowShares"
    Invoke-Expression "cmd /c start powershell -NoExit -Command '& $scriptPath'"
}

function startProcess($name) {
    $scriptPath = $PSScriptRoot + "\Modules\" + $name
    Invoke-Expression "cmd /c start powershell -NoExit -Command '& $scriptPath'"
}

function RunEverything {
    startProcess -name "users.ps1"
    startProcess -name "files.ps1"
    Applications
    startProcess -name "policies.ps1"
    startProcess -name "firewall.bat"
    startProcess -name "services.ps1"
    startProcess -name "miscellaneous.bat"
    startProcess -name "windowsDefender.ps1"
}

function extraTools {
    do {
        ToolsSelectionMenu
        $Selection = Read-Host "Option"
        Switch ($Selection){
            '1' {
                startProcess("fileTool.ps1")
            } '2' {
                startProcess("processes.ps1")
            } '3' {
                startProcess("stigChecker.ps1")
            } '4' {
                startProcess("baseProcesses.ps1")
            } '5' {
                return
            }
        }
        pause
    } until ($Selection -eq '3')
}

$DUMP = ($PSScriptRoot + "\dump\")
if (-not (Test-Path -Path $DUMP)) {
    New-Item -ItemType Directory -Path ($DUMP)
}
Write-Host "Welcome to the execution of the Calamity script. First please answer a few questions"
$RDP = Read-Host -Prompt "Enable Remote Desktop? (Y/N)"
$SMB = Read-Host -Prompt "Enable SMB? (Y/N)"
$AllowShares = Read-Host -Prompt "Remove Shares? (Y/N)"
$SecurePrinters = Read-Host -Prompt "Secure Printers? (Y/N)"

Write-Host "Some of the script relies on the Powershell version being v7." -NoNewline
$PowershellSpecificVersionRequired = Read-Host -Prompt " Is a specific version required (i.e. does the readme say 'Do not upgrade to Powershell v7' or something like that? (Y/N)"
if ($PowershellSpecificVersionRequired -eq "N") {
    iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI"
}

do {
    SelectionMenu
    $Selection = Read-Host "Option"
    Switch ($Selection){
        '1' {
            RunEverything
        } '2' {
            startProcess -name "policies.ps1"
        } '3' {
            startProcess -name "users.ps1"
        } '4' {
            startProcess -name "firewall.bat"
        } '5' {
            Applications -RDP $RDP -SMB $SMB -AllowShares $AllowShares
        } '6' {
            startProcess -name "services.ps1"
        } '7' {
            startProcess -name "miscellaneous.bat"
        } '8' { 
            $RDP = Read-Host -Prompt "Enable Remote Desktop? (Y/N)"
            $SMB = Read-Host -Prompt "Enable SMB? (Y/N)"
            $AllowShares = Read-Host -Prompt "Remove Shares? (Y/N)"
        } '9' {
            startProcess -name "files.ps1"
        } '10' {
            startProcess -name "windowsDefender.ps1"
        } '11' {
            extraTools
            return
        } '12' {
            startProcess -name "apps.ps1"
        } '13' {
            return
        }
    }
    pause
} until ($Selection -eq '11' -or $Selection -eq '13')