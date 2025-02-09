function checkProcesses(){
    $NonDefaultServices = Get-wmiobject win32_service | Where-Object { $_.Caption -notmatch "Windows" -and $_.PathName -notmatch "Windows" -and
    $_.PathName -notmatch "policyhost.exe" -and $_.Name -ne "LSM" -and $_.PathName -notmatch "OSE.EXE" -and $_.PathName -notmatch
    "OSPPSVC.EXE" -and $_.PathName -notmatch "Microsoft Security Client" }
    foreach ($node in $NonDefaultServices){
    Write-Host $node.DisplayName -ForegroundColor Yellow
    Write-Host "    " -NoNewline
    Write-Host $node.PathName -ForegroundColor cyan -NoNewline
    Write-Host " | " -NoNewline
    if($node.State -eq "Stopped"){
        Write-Host $node.State -ForegroundColor red 
    }
    else{
        Write-Host $node.State -ForegroundColor green 
    }
}}

checkProcesses