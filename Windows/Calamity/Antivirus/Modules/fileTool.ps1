param (
    [string]$path,
    [string]$fileExtension
  )
  $host.ui.RawUI.WindowTitle = "File Tool: $fileExtension"
  $signedFiles = @()
  $unsignedFiles = @()

  # Recursively search for files with the specified extension in the input path
  $files = Get-ChildItem -Path $path -Recurse -Include "*.$fileExtension" -Force -ErrorAction SilentlyContinue

  # Iterate through each file
  foreach ($file in $files) {
    try {
        if (!($file.Fullname -match "WinSxS") -and !($file.Fullname -match "assembly") -and !($file.Fullname -match "servicing")){
            $signature = Get-AuthenticodeSignature $file.FullName
            if ($signature.Status -eq "Valid") {
                $signedFiles += $file
                $copyrightStuff = (Get-Item $file.FullName)
                if(($signature.SignerCertificate.Issuer -match 'Microsoft Windows') -or ($copyrightStuff.VersionInfo.LegalCopyright -match 'Microsoft Corporation') -or ($copyrightStuff.VersionInfo.LegalCopyright -match 'VMware')){}
                else {
                    Write-Warning "$file"
                }
            }
            else{
                $unsignedFiles += $file
            }
        }
    }
    catch {
        # Ignore any permission errors and continue checking other files
        Write-Warning "Error accessing file: $file.FullName. Error: $_"
    }
  }

  foreach ($file in $unsignedFiles) {
    Write-Host $file.FullName
  }