# Helper Functions
function Get-RegistryValue($path, $key) {
    Write-Host "Checking $path\$key"
    (Get-Item -LiteralPath $path -ErrorAction SilentlyContinue).GetValue($key, $null)
}

# WINDOWS DEFENDER STUFF

function Check-WindowsDefenderSTIG {
    # STIG V-213452
    # Value should be between 1 and 6 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" "ASSignatureDue"
    Write-Host "STIG V-213452 met: " -NoNewline
    if (($output -ge 1) -or ($output -le 7)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213453
    # Value should be between 1 and 6 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" "AVSignatureDue"
    Write-Host "STIG V-213453 met: " -NoNewline
    if  (($output -ge 1) -or ($output -le 7)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213428
    # Value should be null (-eq $null should work for testing)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender" "DisableAntiSpyware"
    Write-Host "STIG V-213428 met: " -NoNewline
    if  ($output -eq $null) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213426
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender" "PUAProtection"
    Write-Host "STIG V-213426 met: " -NoNewline
    if  ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213458
    # Value should be 1 (REG_SZ)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "3B576869-A4EC-4529-8536-B80A7769E899"
    Write-Host "STIG V-213458 met: " -NoNewline
    if  ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213459
    # Value should be 1 (REG_SZ)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"
    Write-Host "STIG V-213459 met: " -NoNewline
    if  ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213450
    # Value should be between 0x0 through 0x7 (REG_DWORD) (Should not be 0x8)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" "ScheduleDay"
    Write-Host "STIG V-213450 met: " -NoNewline
    if  (($output -ge 0) -or ($output -le 7)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213451
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" "DisableEmailScanning"
    Write-Host "STIG V-213451 met: " -NoNewline
    if  ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213456
    # Value should be 1 (REG_SZ)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"
    Write-Host "STIG V-213456 met: " -NoNewline
    if  ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213457
    # Value should be 1 (REG_SZ)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"
    Write-Host "STIG V-213457 met: " -NoNewline
    if  ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213454
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates" "ScheduleDay"
    Write-Host "STIG V-213454 met: " -NoNewline
    if  ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213455
    # Value should be 2 or 3 (REG_SZ)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" "5"
    Write-Host "STIG V-213455 met: " -NoNewline
    if  (($output -eq 2) -or ($output -eq 3)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213438
    # Value should be $null (should not exist) or 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" "LocalSettingOverrideRealtimeScanDirection"
    Write-Host "STIG V-213438 met: " -NoNewline
    if  (($output -eq $null) -or ($output -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213439
    # Value should be $null (should not exist) or 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" "LocalSettingOverrideDisableIOAVProtection"
    Write-Host "STIG V-213439 met: " -NoNewline
    if  (($output -eq $null) -or ($output -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213430
    # Value should be $null (should not exist)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions" "Exclusions_Processes"
    Write-Host "STIG V-213430 met: " -NoNewline
    if  ($output -eq $null) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213431
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions" "DisableAutoExclusions"
    Write-Host "STIG V-213431 met: " -NoNewline
    if  ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213432
    # Value should be $null (should not exist) or 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" "LocalSettingOverrideSpynetReporting"
    Write-Host "STIG V-213432 met: " -NoNewline
    if  (($output -eq $null) -or ($output -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213433
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" "DisableBlockAtFirstSeen"
    Write-Host "STIG V-213433 met: " -NoNewline
    if  ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213434
    # Value should be 2 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" "SpynetReporting"
    Write-Host "STIG V-213434 met: " -NoNewline
    if  ($output -eq 2) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213436
    # Value should be $null (should not exist) or 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\NIS" "DisableProtocolRecognition"
    Write-Host "STIG V-213436 met: " -NoNewline
    if  (($output -eq $null) -or ($output -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213437 
    # Value should be $null (should not exist) or 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" "LocalSettingOverrideDisableOnAccessProtection"
    Write-Host "STIG V-213437 met: " -NoNewline
    if  (($output -eq $null) -or ($output -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213449
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" "DisableRemovableDriveScanning"
    Write-Host "STIG V-213449 met: " -NoNewline
    if  ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213448
    # Value should be $null (should not exist) or 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" "DisableArchiveScanning"
    Write-Host "STIG V-213448 met: " -NoNewline
    if  (($output -eq $null) -or ($output -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213445
    # Value should be $null (should not exist) or 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring"
    Write-Host "STIG V-213445 met: " -NoNewline
    if  (($output -eq $null) -or ($output -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213444
    # Value should be $null (should not exist) or 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableIOAVProtection"
    Write-Host "STIG V-213444 met: " -NoNewline
    if  (($output -eq $null) -or ($output -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213447
    # Value should be $null (should not exist) or 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableScanOnRealtimeEnable"
    Write-Host "STIG V-213447 met: " -NoNewline
    if  (($output -eq $null) -or ($output -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213446
    # Value should be $null (should not exist) or 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableBehaviorMonitoring"
    Write-Host "STIG V-213446 met: " -NoNewline
    if  (($output -eq $null) -or ($output -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213441
    # Value should be $null (should not exist) or 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" "LocalSettingOverrideDisableRealtimeMonitoring"
    Write-Host "STIG V-213441 met: " -NoNewline
    if  (($output -eq $null) -or ($output -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213440
    # Value should be $null (should not exist) or 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" "LocalSettingOverrideDisableBehaviorMonitoring"
    Write-Host "STIG V-213440 met: " -NoNewline
    if  (($output -eq $null) -or ($output -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213443
    # Value should be $null (should not exist) or 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableOnAccessProtection"
    Write-Host "STIG V-213443 met: " -NoNewline
    if  (($output -eq $null) -or ($output -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213442
    # Value should be $null (should not exist) or 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" "RealtimeScanDirection"
    Write-Host "STIG V-213442 met: " -NoNewline
    if  (($output -eq $null) -or ($output -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213466
    # Value should be 2 or 3 (REG_SZ)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" "1"
    Write-Host "STIG V-213466 met: " -NoNewline
    if  (($output -eq 2) -or ($output -eq 3)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213429
    # Value should be $null (should not exist)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions" "Exclusions_Paths"
    Write-Host "STIG V-213429 met: " -NoNewline
    if  ($output -eq $null) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213463
    # Value should be 1
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" "EnableNetworkProtection"
    Write-Host "STIG V-213463 met: " -NoNewline
    if  ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213462
    # Value should be 1 (REG_SZ)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"
    Write-Host "STIG V-213462 met: " -NoNewline
    if  ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213461
    # Value should be 1 (REG_SZ)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"
    Write-Host "STIG V-213461 met: " -NoNewline
    if  ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213460
    # Value should be 1 (REG_SZ)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "D3E037E1-3EB8-44C8-A917-57927947596D"
    Write-Host "STIG V-213460 met: " -NoNewline
    if  ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213427
    # Value should be $null (should not exist) or 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender" "DisableRoutinelyTakingAction"
    Write-Host "STIG V-213427 met: " -NoNewline
    if  (($output -eq $null) -or ($output -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213465
    # Value should be 2 or 3 (REG_SZ)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" "2"
    Write-Host "STIG V-213465 met: " -NoNewline
    if  (($output -eq 2) -or ($output -eq 3)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    
    # STIG V-213464
    # Value should be 2 or 3 (REG_SZ)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" "4"
    Write-Host "STIG V-213464 met: " -NoNewline
    if  (($output -eq 2) -or ($output -eq 3)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
}

# Windows 10 Checker

function Check-Windows10STIG {
    # STIG V-220932
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "RestrictNullSessAccess"
    Write-Host "STIG V-220932 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220930
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous"
    Write-Host "STIG V-220930 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220937
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoLMHash"
    Write-Host "STIG V-220937 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220938
    # Value should be 5 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
    Write-Host "STIG V-220938 met: " -NoNewline
    if ($output -eq 5) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220823
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowToGetHelp"
    Write-Host "STIG V-220823 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220828
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun"
    Write-Host "STIG V-220828 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220726
    # nx should have OptOut or AlwaysOn
    Write-Host "STIG V-220726 met: " -NoNewline
    if ((BCDedit /enum "{current}" | Select-String -Pattern 'nx').ToString().Contains("OptOut")) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }

    # STIG V-220727
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation"
    Write-Host "STIG V-220727 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220857
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"
    Write-Host "STIG V-220857 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220827
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoAutoplayfornonVolume"
    Write-Host "STIG V-220827 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220862
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowBasic"
    Write-Host "STIG V-220862 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220865
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowBasic"
    Write-Host "STIG V-220865 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220812
    # Value should contain 1
    (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning.Contains(1) # may not work?
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" "LsaCfgFlags"
    Write-Host "STIG V-220812 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220929
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM"
    Write-Host "STIG V-220929 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220829
    # Value should be 255 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" "NoDriveTypeAutoRun"
    Write-Host "STIG V-220829 met: " -NoNewline
    if ($output -eq 255) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220830
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" "EnhancedAntiSpoofing"
    Write-Host "STIG V-220830 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220836
    # value should be 1 (REG_DWORD)
    $output1=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen"
    # value should be Block (REG_SZ)
    $output2=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "ShellSmartScreenLevel"
    Write-Host "STIG V-220836 met: " -NoNewline
    if (($output1 -eq 1) -and ($output2 -eq "Block")) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220837
    # Value should be $null (should not exist) or 0
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDataExecutionPrevention"
    Write-Host "STIG V-220837 met: " -NoNewline
    if (($output -eq $null) -or ($output -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220834
    # Value should be 0 or 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry"
    Write-Host "STIG V-220834 met: " -NoNewline
    if (($output -eq 0) -or ($output -eq 1)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220703
    # Value should be 1 (REG_DWORD)
    $output1=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "UseAdvancedStartup"
    # Value should be 1 (REG_DWORD)
    $output2=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "UseTPMPin"
    # Value should be 1 (REG_DWORD)
    $output3=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "UseTPMKeyPin"
    Write-Host "STIG V-220703 met: " -NoNewline
    if (($output1 -eq 1) -and ($output2 -eq 1) -and ($output3 -eq 1)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220704
    # Value should be greater than or equal to 6 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\FVE" "MinimumPIN"
    Write-Host "STIG V-220704 met: " -NoNewline
    if ($output -ge 6) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220933
    # Value should be equal to 'O:BAG:BAD:(A;;RC;;;BA)' (REG_SZ)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictRemoteSAM"
    Write-Host "STIG V-220933 met: " -NoNewline
    if ($output -eq "O:BAG:BAD:(A;;RC;;;BA)") {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220931
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous"
    Write-Host "STIG V-220931 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220936
    # Value should be 2147483640 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" "SupportedEncryptionTypes"
    Write-Host "STIG V-220936 met: " -NoNewline
    if ($output -eq 2147483640) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220935
    # Value should be 0
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u" "AllowOnlineID"
    Write-Host "STIG V-220935 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220934
    # Value should be 0
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" "allownullsessionfallback"
    Write-Host "STIG V-220934 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220939
    # Value should be 2
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" "LDAPClientIntegrity"
    Write-Host "STIG V-220939 met: " -NoNewline
    if ($output -eq 2) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220824
    # Value should be 1
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" "RestrictRemoteClients"
    Write-Host "STIG V-220824 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220821
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" "DCSettingIndex"
    Write-Host "STIG V-220821 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220820
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnumerateLocalUsers"
    Write-Host "STIG V-220820 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220822
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" "ACSettingIndex"
    Write-Host "STIG V-220822 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220902
    # Value should be 0
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection" "DeviceEnumerationPolicy"
    Write-Host "STIG V-220902 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220819
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DontDisplayNetworkSelectionUI"
    Write-Host "STIG V-220819 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220780
    # Value should be greater than or equal to 1024000 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "MaxSize"
    Write-Host "STIG V-220780 met: " -NoNewline
    if ($output -ge 1024000) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220781
    # Value should be greater than or equal to 32768
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" "MaxSize"
    Write-Host "STIG V-220781 met: " -NoNewline
    if ($output -ge 32768) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220839
    # Value should be $null (should not exist) or 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "PreXPSP2ShellProtocolBehavior"
    Write-Host "STIG V-220839 met: " -NoNewline
    if (($output -eq $null) -or ($output -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220919
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireStrongKey"
    Write-Host "STIG V-220919 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220728
    # Should be false (means Powershell v2 is not installed)
    $output = (-Not ((Get-WindowsOptionalFeature -Online | Where FeatureName -like *PowerShellv2*) | ForEach-Object -Process { $_.State -eq "Enabled" }))
    Write-Host "STIG V-220728 met: " -NoNewline
    if ((-Not $output[0]) -and (-Not $output[1])) {
       Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }

    # STIG V-220729
    # Should be False (Means SMB 1.0 is not enabled)
    Write-Host "STIG V-220729 met: " -NoNewline
    if ( -Not (Get-WindowsOptionalFeature -Online | Where FeatureName -eq SMB1Protocol | ForEach-Object -Process { $_.State -eq "Enabled" })) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }

    # STIG V-220915
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SealSecureChannel"
    Write-Host "STIG V-220915 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220914
    # Value should be 1
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireSignOrSeal"
    Write-Host "STIG V-220914 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220720
    # Should be false (means Simple TCP/IP Services are not installed)
    Write-Host "STIG V-220720 met: " -NoNewline 
    if (-Not (Get-WindowsOptionalFeature -Online | Where FeatureName -eq SimpleTCP | ForEach-Object -Process { $_.State -eq "Enabled" })) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }

    # STIG V-220721
    # Should be false (means Telnet Client is not installed)
    Write-Host "STIG V-220721 met: " -NoNewline 
    if (-Not (Get-WindowsOptionalFeature -Online | Where FeatureName -eq TelnetClient | ForEach-Object -Process { $_.State -eq "Enabled" })) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }

    # STIG V-220850
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fPromptForPassword"
    Write-Host "STIG V-220850 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220851
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fEncryptRPCTraffic"
    Write-Host "STIG V-220851 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220852
    # Value should be 3 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MinEncryptionLevel"
    Write-Host "STIG V-220852 met: " -NoNewline
    if ($output -eq 3) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220853
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "DisableEnclosureDownload"
    Write-Host "STIG V-220853 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220854
    # Value should be $null or 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "AllowBasicAuthInClear"
    Write-Host "STIG V-220854 met: " -NoNewline
    if (($output -eq $null) -or ($output -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220855
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowIndexingEncryptedStoresOrItems"
    Write-Host "STIG V-220855 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220856
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "EnableUserControl"
    Write-Host "STIG V-220856 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220858
    # Value should be $null or 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "SafeForScripting"
    Write-Host "STIG V-220858 met: " -NoNewline
    if (($output -eq $null) -or ($output -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220859
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableAutomaticRestartSignOn"
    Write-Host "STIG V-220859 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220866
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowUnencryptedTraffic"
    Write-Host "STIG V-220866 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220793
    # The value should exist (!= $null)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" "Deny"
    Write-Host "STIG V-220793 met: " -NoNewline
    if ($output -ne $null) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220792
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera"
    Write-Host "STIG V-220792 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220796
    # Value should be 2 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "DisableIPSourceRouting"
    Write-Host "STIG V-220796 met: " -NoNewline
    if ($output -eq 2) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220795
    # Value should be 2 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisableIPSourceRouting"
    Write-Host "STIG V-220795 met: " -NoNewline
    if ($output -eq 2) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220794
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow"
    Write-Host "STIG V-220794 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220799
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LocalAccountTokenFilterPolicy"
    Write-Host "STIG V-220799 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220731
    # Value should be 4 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start"
    Write-Host "STIG V-220731 met: " -NoNewline
    if ($output -eq 4) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220730
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1"
    Write-Host "STIG V-220730 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220732
    # Value should be true (means service is disabled)
    Write-Host "STIG V-220732 met: " -NoNewline
    if (((Get-Service -Name seclogon).StartType -eq "Disabled")) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220843
    # Value should be "no" (REG_SZ)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" "FormSuggest Passwords"
    Write-Host "STIG V-220843 met: " -NoNewline
    if ($output -eq "no") {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220842
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings" "PreventCertErrorOverrides"
    Write-Host "STIG V-220842 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220841
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" "PreventOverrideAppRepUnknown"
    Write-Host "STIG V-220841 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220840
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" "PreventOverride"
    Write-Host "STIG V-220840 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220847
    # Value should be 6 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" "MinimumPINLength"
    Write-Host "STIG V-220847 met: " -NoNewline
    if ($output -eq 6) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220846
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" "RequireSecurityDevice"
    Write-Host "STIG V-220846 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220845
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR"
    Write-Host "STIG V-220845 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220844
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" "EnabledV9"
    Write-Host "STIG V-220844 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220849
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableCdm"
    Write-Host "STIG V-220849 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220848
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DisablePasswordSaving"
    Write-Host "STIG V-220848 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220926
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnablePlainTextPassword"
    Write-Host "STIG V-220926 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220832
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" "EnumerateAdministrators"
    Write-Host "STIG V-220832 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220876
    # SEHOP: Enable should be ON or NOTSET
    # below command should return True
    Write-Host "STIG V-220876 met: " -NoNewline
    if (((Get-ProcessMitigation -System).SEHOP.Enable -ne "OFF")) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220877
    # Heap: TerminateOnError should be ON or NOTSET
    # below command should return True
    Write-Host "STIG V-220877 met: " -NoNewline
    if (((Get-ProcessMitigation -System).Heap.TerminateOnError -ne "OFF")) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220874
    # ASLR: BottomUp should be ON or NOTSET
    # below command should return True
    Write-Host "STIG V-220874 met: " -NoNewline
    if (((Get-ProcessMitigation -System).ASLR.BottomUp -ne "OFF")) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220875
    # CFG: Enable should be ON or NOTSET
    # below command should return True
    Write-Host "STIG V-220875 met: " -NoNewline
    if (((Get-ProcessMitigation -System).CFG.Enable -ne "OFF")) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220873
    # DEP: Enable should be ON or NOTSET
    # below command should return True
    Write-Host "STIG V-220873 met: " -NoNewline
    if (((Get-ProcessMitigation -System).DEP.Enable -ne "OFF")) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220870
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\Windows\System" "AllowDomainPINLogon"
    Write-Host "STIG V-220870 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220871
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace" "AllowWindowsInkWorkspace"
    Write-Host "STIG V-220871 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220818
    # Value should be $null (should not exist) or 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" "DevicePKInitEnabled"
    Write-Host "STIG V-220818 met: " -NoNewline
    if (($output -eq $null) -or ($output -eq 1)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220800
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest" "UseLogonCredential"
    Write-Host "STIG V-220800 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220910
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse"
    Write-Host "STIG V-220910 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220810
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowProtectedCreds"
    Write-Host "STIG V-220810 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220940
    # Value should be 537395200 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinClientSec"
    Write-Host "STIG V-220940 met: " -NoNewline
    if ($output -eq 537395200) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220941
    # Value should be 537395200 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NTLMMinServerSec"
    Write-Host "STIG V-220941 met: " -NoNewline
    if ($output -eq 537395200) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220861
    # Value should be 1 (REG_DWORD)
    $output1=Get-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoPreviewPane"
    # Value should be 1 (REG_DWORD)
    $output2=Get-RegistryValue "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoReadingPane"
    Write-Host "STIG V-220861 met: " -NoNewline
    if (($output1 -eq 1) -and ($output2 -eq 1)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220722
    # Should return false
    Write-Host "STIG V-220722 met: " -NoNewline
    if (-Not (Get-WindowsOptionalFeature -Online | Where FeatureName -eq TFTP | ForEach-Object -Process { $_.State -eq "Enabled" })) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }

    # STIG V-220916
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SignSecureChannel"
    Write-Host "STIG V-220916 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220955
    # Value should be $null (should not exist) or 2 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" "SaveZoneInformation"
    Write-Host "STIG V-220955 met: " -NoNewline
    if (($output -eq $null) -or ($output -eq 2)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220951
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableVirtualization"
    Write-Host "STIG V-220951 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220814
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoGPOListChanges"
    Write-Host "STIG V-220814 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220815
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableWebPnPDownload"
    Write-Host "STIG V-220815 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220816
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoWebServices"
    Write-Host "STIG V-220816 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220817
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableHTTPPrinting"
    Write-Host "STIG V-220817 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220813
    # Value should be 1, 3 or 8 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" "DriverLoadPolicy"
    Write-Host "STIG V-220813 met: " -NoNewline
    if (($output -eq 1) -or ($output -eq 3) -or ($output -eq 8)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220868
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowDigest"
    Write-Host "STIG V-220868 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220947
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorUser"
    Write-Host "STIG V-220947 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220944
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "FilterAdministratorToken"
    Write-Host "STIG V-220944 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220945
    # Value should be 2 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin"
    Write-Host "STIG V-220945 met: " -NoNewline
    if ($output -eq 2) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220860
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
    Write-Host "STIG V-220860 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220948
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableInstallerDetection"
    Write-Host "STIG V-220948 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220942
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" "Enabled"
    Write-Host "STIG V-220942 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220949
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableSecureUIAPaths"
    Write-Host "STIG V-220949 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220809
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled"
    Write-Host "STIG V-220809 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220808
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM"
    Write-Host "STIG V-220808 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220807
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fBlockNonDomain"
    Write-Host "STIG V-220807 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220806
    # Value should be $null (should not exist) or 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fMinimizeConnections"
    Write-Host "STIG V-220806 met: " -NoNewline
    if (($output -eq $null) -or ($output -eq 1)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220805
    # Value should be 'NistP384 NistP256' (REG_MULTI_SZ)
    $output = Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" "EccCurves"
    Write-Host "STIG V-220805 met: " -NoNewline
    if (($output[0] -eq "NistP384") -and ($output[1] -eq "NistP256")) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220804
    # Value should be "RequireMutualAuthentication=1, RequireIntegrity=1" (REG_SZ)
    $output1=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\NETLOGON"
    # Value should be "RequireMutualAuthentication=1, RequireIntegrity=1" (REG_SZ)
    $output2=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" "\\*\SYSVOL"
    Write-Host "STIG V-220804 met: " -NoNewline
    if (($output1 -eq "RequireMutualAuthentication=1, RequireIntegrity=1") -and ($output2 -eq "RequireMutualAuthentication=1, RequireIntegrity=1")) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220803
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_ShowSharedAccessUI"
    Write-Host "STIG V-220803 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220802
    # Value should be 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" "AllowInsecureGuestAuth"
    Write-Host "STIG V-220802 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220801
    # Value should be 4096 (REG_DWORD)
    $output1=Get-RegistryValue "HKLM:\SOFTWARE\Classes\batfile\shell\runasuser" "SuppressionPolicy"
    $output2=Get-RegistryValue "HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser" "SuppressionPolicy"
    $output3=Get-RegistryValue "HKLM:\SOFTWARE\Classes\exefile\shell\runasuser" "SuppressionPolicy"
    $output4=Get-RegistryValue "HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser" "SuppressionPolicy"
    Write-Host "STIG V-220801 met: " -NoNewline
    if (($output1 -eq 4096) -and ($output2 -eq 4096) -and ($output3 -eq 4096) -and ($output4 -eq 4096)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220920
    # Value should be 300 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs"
    Write-Host "STIG V-220920 met: " -NoNewline
    if ($output -eq 300) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220924
    # Value should be 1 or 2 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "SCRemoveOption"
    Write-Host "STIG V-220924 met: " -NoNewline
    if (($output -eq 1) -or ($output -eq 2)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220925
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature"
    Write-Host "STIG V-220925 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220869
    # Value should be 2 (REG_DWORD)
    $output1=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsActivateWithVoiceAboveLock"
    # Value should be 2 (REG_DWORD)
    $output2=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsActivateWithVoice"
    Write-Host "STIG V-220869 met: " -NoNewline
    if (($output1 -eq 2) -and ($output2 -eq 2)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220927
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "RequireSecuritySignature"
    Write-Host "STIG V-220927 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220867
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "DisableRunAs"
    Write-Host "STIG V-220867 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220950
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
    Write-Host "STIG V-220950 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-230220
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting"
    Write-Host "STIG V-230220 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220831
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures"
    Write-Host "STIG V-220831 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220835
    # Value should be 0 (REG_DWORD)
    $output1=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode"
    # Value should be 0 (REG_DWORD)
    $output2=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" "DODownloadMode"
    Write-Host "STIG V-220835 met: " -NoNewline
    if (($output1 -eq 0) -and ($output2 -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220838
    # Value should be $null (should not exist) or 0 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoHeapTerminationOnCorruption"
    Write-Host "STIG V-220838 met: " -NoNewline
    if (($output -eq $null) -or ($output -eq 0)) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220825
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "MSAOptional"
    Write-Host "STIG V-220825 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220918
    # Value should be 30 or less
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "MaximumPasswordAge"
    Write-Host "STIG V-220918 met: " -NoNewline
    if ($output -le 30) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220797
    # Value should be 0
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "EnableICMPRedirect"
    Write-Host "STIG V-220797 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220798
    # Value should be 1
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" "NoNameReleaseOnDemand"
    Write-Host "STIG V-220798 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220826
    # Value should be 1
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" "DisableInventory"
    Write-Host "STIG V-220826 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220872
    # Value should be 1
    $output=Get-RegistryValue "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableThirdPartySuggestions"
    Write-Host "STIG V-220872 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220917
    # Value should be 0
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "DisablePasswordChange"
    Write-Host "STIG V-220917 met: " -NoNewline
    if ($output -eq 0) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220954
    # Value should be 1
    $output=Get-RegistryValue "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoToastApplicationNotificationOnLockScreen"
    Write-Host "STIG V-220954 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220923
    # Value should be less than or equal to 10
    $output=Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount"
    Write-Host "STIG V-220923 met: " -NoNewline
    if ($output -le 10) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
    # STIG V-220943
    # Value should be 1 (REG_DWORD)
    $output=Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "ProtectionMode"
    Write-Host "STIG V-220943 met: " -NoNewline
    if ($output -eq 1) {
        Write-Host -ForegroundColor Green "True"
    } else {
        Write-Host -ForegroundColor Red "False"
    }
}

Check-WindowsDefenderSTIG
Check-Windows10STIG