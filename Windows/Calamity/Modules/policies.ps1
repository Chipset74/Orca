function Set-Windows10LocalGroupPolicy {
    $lgpoEXEPath = $PSScriptRoot + "\..\Executables\LGPO.exe"
    $perfectPath = $PSScriptRoot + "\..\Perfect\"
    Copy-Item ($perfectPath + "Windows10_GroupPolicy\*") -Destination "C:\Windows\System32\GroupPolicy" -Recurse -Force
    gpupdate /force
    & $lgpoEXEPath /m ($perfectPath + "TestingDomainSysvol\Machine\registry.pol")
    & $lgpoEXEPath /u ($perfectPath + "TestingDomainSysvol\User\registry.pol")
    & $lgpoEXEPath /s ($perfectPath + "TestingDomainSysvol\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf")
    & $lgpoEXEPath /ac ($perfectPath + "TestingDomainSysvol\Machine\microsoft\windows nt\Audit\audit.csv")

    # NOTE: The following code assumes all the registry keys are of value REG_DWORD (PS Equivalent: DWord). 
    # If you need to add a registry key not of that type, you need to add it to the below hash map and account for it in the for loop
    $registries = @{
        registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel",
                        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowSignInOptions",
                        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config",
                        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config",
                        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search",
                        "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config",
                        "HKLM:\Software\Policies\Microsoft\Windows\OneDrive",
                        "HKLM:\Software\Policies\Microsoft\Windows\OneDrive",
                        "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                        "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
                        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                        "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10",
                        "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest",
                        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}",
                        "HKLM:\SOFTWARE\Classes\batfile\shell\runasuser",
                        "HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser",
                        "HKLM:\SOFTWARE\Classes\exefile\shell\runasuser",
                        "HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser",
                        "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                        "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters",
                        "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
                        "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy";
        registryName = "DisableExceptionChainValidation",
                        "value",
                        "DownloadMode",
                        "DODownloadMode",
                        "AllowCortana",
                        "AutoConnectAllowedOEM",
                        "DisableFileSyncNGSC",
                        "DisableFileSync",
                        "DisableIPSourceRouting",
                        "DisableIpSourceRouting",
                        "LocalAccountTokenFilterPolicy",
                        "Start",
                        "SMB1",
                        "UseLogonCredential",
                        "NoGPOListChanges",
                        "SuppressionPolicy",
                        "SuppressionPolicy",
                        "SuppressionPolicy",
                        "SuppressionPolicy",
                        "EnableICMPRedirect",
                        "NoNameReleaseOnDemand",
                        "DisableIPSourceRouting",
                        "DisableIPSourceRouting",
                        "Enabled";
        registryValue = 0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        1,
                        1,
                        2,
                        2,
                        0,
                        4,
                        0,
                        0,
                        0,
                        4096,
                        4096,
                        4096,
                        4096,
                        0,
                        1,
                        2,
                        2,
                        0,
                        1;
    }
    for ($i = 0; $i -le ($registries.registryPath.length - 1); $i++) {
        $registryPath = $registries.registryPath[$i]
        $name = $registries.registryName[$i]
        $value = $registries.registryValue[$i]
        # If registry path doesn't exist, create it.
        If (-NOT (Test-Path $registryPath)) {
            Write-Host "Registry path $registryPath does not exist. Creating now"
            New-Item $registryPath -Force | Out-Null
        }

        New-ItemProperty -Path $registryPath `
            -Name $name `
            -Value $value `
            -PropertyType DWord `
            -Force | Out-Null
    }
}


$os = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption

if ($os.Caption.ToLower().Contains('windows 10')) {
    Write-Host "Current Operating System is Windows 10"
    Set-Windows10LocalGroupPolicy
} else {
    Write-Host "Unkown operating system"
    Set-Windows10LocalGroupPolicy
}