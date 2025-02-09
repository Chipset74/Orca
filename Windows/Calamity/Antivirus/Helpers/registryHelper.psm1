function GetRegistryKeyValue {
    param(
        [string]$Path
    )

    try {
        $Name = $Path.Split("\")[-1]
        $Path = ($Path.Split("\")[0..($Path.Split("\").Count-2)] -join "\")
        $key = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop
        return $key
    } catch {
        return $null
    }
}

Export-ModuleMember -Function GetRegistryKeyValue