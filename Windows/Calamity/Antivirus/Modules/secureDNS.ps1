
# CVE-2020-25705
$key = "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
$value = "1221"
New-ItemProperty -Path $key -Name "MaximumUdpPacketSize" -Value $value -PropertyType DWORD -Force

# Rate Limiting Enabled
Set-DnsServerResponseRateLimiting -ResetToDefault -Force
Set-DnsServerRRL -Force

# Disable IPv6 to IPv4 Tunneling
$key = "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
$value = "wpad`n isatap"
New-ItemProperty -Path $key -Name "GlobalQueryBlockList" -Value $value -PropertyType MultiString -Force
