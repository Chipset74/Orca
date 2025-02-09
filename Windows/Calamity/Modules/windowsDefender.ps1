function removeExclusions(){
    #https://georgik.rocks/quick-way-to-clear-all-windows-defender-exclusions/
    $Paths=(Get-MpPreference).ExclusionPath
    foreach ($Path in $Paths) { 
        Remove-MpPreference -ExclusionPath $Path 
        Write-Output "Deleted Path Exclusion: " + $Path
    }

    $Extensions=(Get-MpPreference).ExclusionExtension
    foreach ($Extension in $Extensions) { 
        Remove-MpPreference -ExclusionExtension $Extension 
        Write-Output "Deleted Extension Exclusion: " + $Extension
    }
    
    $Processes=(Get-MpPreference).ExclusionProcess
    foreach ($Process in $Processes) { 
        Remove-MpPreference -ExclusionProcess $Process 
        Write-Output "Deleted Proccess Exclusion: " + $Process
    }
}

function enableProtections(){
    Set-MpPreference -EnableControlledFolderAccess Enabled #Ransomware Controller Folder Access
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios" -Name "HypervisorEnforcedCodeIntegrity" -Value 1 -ErrorAction SilentlyContinue
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios" -Name "HypervisorEnforcedCodeIntegrity" -Value 1 -ErrorAction SilentlyContinue #HypervisorEnforcedCodeIntegrity   
    Set-ProcessMitigation -System -Enable TerminateOnError #Validate Heap Integrity
    Set-ProcessMitigation -System -Enable SEHOP 
    Set-ProcessMitigation -System -Enable CFG 
    Set-ProcessMitigation -System -Enable BottomUp
    Set-ProcessMitigation -System -Enable DEP 
    Set-MpPreference -DisableRealtimeMonitoring 0 #RealTime Monitoring
    BCDEdit /set "{current}" nx OptOut # STIG V-220726
}

enableProtections
