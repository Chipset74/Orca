# Administrator, DefaultAccount, Guest, WDAGUtilityAccount

$DUMP = ($PSScriptRoot + "\..\dump\")


$SecureStdPass = ConvertTo-SecureString "I<3Scripts!" -AsPlainText -Force

function verifyUsersAreNotLockedOut() {
    Get-LocalUser | ForEach-Object {
        #TODO
    }
}

function automaticUsersPrep() {
    $URL = Get-Content ("C:\CyberPatriot\README.url")
    $Regex = [Regex]::new('(?<=")(.*)(?=")')
    $Match = $Regex.Match($URL)
    if ($Match.Success) {
        $URL = $Match.Value
    }
    $array2 = $URL | select-string -pattern '\b(?:(?:https?|ftp|file)://|www\.|ftp\.)(?:\([-A-Z0-9+&@#/%=~_|$?!:,.]*\)|[-A-Z0-9+&@#/%=~_|$?!:,.])*(?:\([-A-Z0-9+&@#/%=~_|$?!:,.]*\)|[A-Z0-9+&@#/%=~_|$])' | % { $_.Matches } | % { $_.Value }
    Write-Output $array2
    Invoke-WebRequest -Uri $array2 -OutFile ($DUMP + "readme.txt")
}

function removeUnauthorizedUsers() {
    $readme = Get-Content ($DUMP + "readme.txt")
    Get-LocalUser | ForEach-Object {
        $currentUser = $_.ToString()
        if ($currentUser.contains("Administrator") -or $currentUser.contains("DefaultAccount") -or $currentUser.contains("Guest") -or $currentUser.contains("WDAGUtilityAccount") -or $currentUser.contains("Big Boi") -or $currentUser.contains("Small Boi")) {
            Write-Output "Built-In Account detected"
        } else {
            $authorizedUser = $readme | Select-String -Pattern $currentUser.TrimEnd() -Quiet
            if (-not($authorizedUser)) {
                Write-Output ($currentUser + " is not authorized")
                Remove-LocalUser -Name $currentUser
            } else {
                Write-Output ($currentUser + " is authorized")
                if (-not($currentUser -eq $env:UserName)) {
                    Set-LocalUser -Name $currentUser -Password $SecureStdPass
                }
                Set-LocalUser -Name $currentUser -PasswordNeverExpires $false
            }
        }
    }   
}

function demoteUnauthorizedAdministrators() {
    $readme = Get-Content ($DUMP + "readme.txt")
    $Regex = [Regex]::new('(?<=Authorized Administrators)(.*)(?=Authorized Users)')
    $Match = $Regex.Match($readme)
    if ($Match.Success) {
        $authorizedAdmin = $Match.Value
    }
    Get-LocalGroupMember -Group "Administrators" | ForEach-Object {
        $localAdmin = (($_ -split "\\")[1])
        if ($localAdmin.contains("Administrator") -or $localAdmin.contains("Big Boi")) {
            Write-Host "Built-In Account Detected"
        } else {
            $isAuthorized = $authorizedAdmin | Select-String -Pattern $localAdmin -Quiet
            if(-not($isAuthorized)) {
                Write-Host "$localAdmin is not admin"
                Remove-LocalGroupMember -Group "Administrators" -Member $localAdmin
            }
        }
    } 
}

automaticUsersPrep
if (-not(Test-Path ($DUMP + "readme.txt"))) {
    Write-Output "It looks like I couldn't download the readme. Please enter URL"
    $URL = Read-Host -Prompt 'URL'
    Invoke-WebRequest -Uri $URL -OutFile ($DUMP + "readme.txt")
    if (-not(Test-Path ($DUMP + "readme.txt"))) {
        Write-Output "Uh-Oh the readme isn't downloading for some reason. Exiting..."
        Exit
    }
}
removeUnauthorizedUsers
demoteUnauthorizedAdministrators
