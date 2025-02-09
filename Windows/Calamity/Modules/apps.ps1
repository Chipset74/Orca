[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#requires -RunAsAdministrator

# Let's go directly to the website and see what it lists as the current version
function updateNotepadPlusPlus {
    $BaseUri = "https://notepad-plus-plus.org"
    $BasePage = Invoke-WebRequest -Uri $BaseUri -UseBasicParsing
    $ChildPath = $BasePage.Links | Where-Object { $_.outerHTML -like '*Current Version*' } | Select-Object -ExpandProperty href
    # Now let's go to the latest version's page and find the installer
    $DownloadPageUri = $BaseUri + $ChildPath
    $DownloadPage = Invoke-WebRequest -Uri $DownloadPageUri -UseBasicParsing
    # Determine bit-ness of O/S and download accordingly
    if ( [System.Environment]::Is64BitOperatingSystem ) {
        $DownloadUrl = $DownloadPage.Links | Where-Object { $_.outerHTML -like '*npp.*.Installer.x64.exe"*' } | Select-Object -ExpandProperty href
    } else {
        $DownloadUrl = $DownloadPage.Links | Where-Object { $_.outerHTML -like '*npp.*.Installer.exe"*' } | Select-Object -ExpandProperty href
    }
    Write-Host "Downloading the latest Notepad++ to the temp folder"
    Invoke-WebRequest -Uri $DownloadUrl -OutFile "$env:TEMP\$( Split-Path -Path $DownloadUrl -Leaf )" | Out-Null
    Write-Host "Installing the latest Notepad++"
    Start-Process -FilePath "$env:TEMP\$( Split-Path -Path $DownloadUrl -Leaf )" -ArgumentList "/S" -Wait
}
function update7zip {
    $dlurl = 'https://7-zip.org/' + (Invoke-WebRequest -Uri 'https://7-zip.org/' | Select-Object -ExpandProperty Links | Where-Object {($_.innerHTML -eq 'Download') -and ($_.href -like "a/*") -and ($_.href -like "*-x64.exe")} | Select-Object -First 1 | Select-Object -ExpandProperty href)
            # above code from: https://perplexity.nl/windows-powershell/installing-or-updating-7-zip-using-powershell/
    $installerPath = Join-Path $env:TEMP (Split-Path $dlurl -Leaf)
    Write-Host "Downloading the latest 7zip"
    Invoke-WebRequest $dlurl -OutFile $installerPath
    Write-Host "Installing hte Latest 7zip"
    Start-Process -FilePath $installerPath -Args "/S" -Verb RunAs -Wait
    Remove-Item $installerPath
}

function removeUneccesaryApps {
    # Removing PowerShellv2 cause it's ancient (ancient = bad)
    Disable-WindowsOptionalFeature -NoRestart -Online -FeatureName MicrosoftWindowsPowerShellV2Root
    Disable-WindowsOptionalFeature -NoRestart -Online -FeatureName TelnetClient
}

function updateApps(){
    updateNotepadPlusPlus
    update7zip
}

updateApps
removeUneccesaryApps