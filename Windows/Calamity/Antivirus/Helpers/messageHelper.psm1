function message {
    param(
        [string]$m
    )
    Write-Host ""
    Write-Host "==============================="
    Write-Host "$m" -ForegroundColor DarkYellow
    Write-Host "==============================="
    Write-Host ""
}
function messageMalware {
    param(
        [string]$m
    )
    Write-Host ""
    Write-Host "--------------------------"
    Write-Host "$m"
    Write-Host "--------------------------"
    Write-Host ""
}

Export-ModuleMember -Function message 
Export-ModuleMember -Function messageMalware