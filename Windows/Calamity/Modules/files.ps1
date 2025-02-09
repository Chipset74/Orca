$DUMP = ($PSScriptRoot + "\..\dump\")
#renames all items in C:\Users that match 
function removeMediaFiles(){
    @("*.png","*.jpg","*.mp4","*.mp3","*.mov","*.avi","*.mpg","*.mpeg","*.flac","*.m4a","*.flv","*.ogg","*.gif","*.jpeg", "*.zip", "*.csv") | 
    ForEach-Object{ 
        Get-ChildItem -Path C:\Users\ -Recurse -Filter $_ 
    } |
    Foreach-Object {
        Rename-Item -Path $_.FullName -NewName ($_.BaseName + "RENAMED" + $_.Extension)
        Write-Output "RENAMED FILE: " + $_
        $_.FullName | Out-File -FilePath ($DUMP + "file-dumps.txt") -Append
    }
}

#TODO - Test This in Next Years Training Images. This is not stable/good enough
function removePrograms(){
    $DefaultWindowsApps = @(
        "Common Files",
        "Internet Explorer",
        "ModifiableWindowsApps",
        "Windows Defender",
        "Windows Mail",
        "Windows Media Player",
        "Windows Multimedia Platform",
        "Windows NT",
        "Windows Photo Viewer",
        "Windows Portable Devices",
        "Windows Security",
        "WindowsPowerShell",
        "Mozilla Firefox"
    )
    
    Get-ChildItem -Path 'C:\Program Files' |
    ForEach-Object {
        Get-ChildItem -Path $_.FullName | 
        ForEach-Object {
            if($DefaultWindowsApps -notcontains $_.Name) {
                if($_.Extension -eq ".exe") {
                    Rename-Item -Path $_.FullName -NewName ($_.BaseName + "RENAMED" + $_.Extension)
                    Write-Output "RENAMED FOLDER: " + $_
                    $_.FullName | Out-File -FilePath ($DUMP + "programFile-dumps.txt") -Append
                }
            }
        }
    }    
}

removeMediaFiles