Write-Host("Verify script is running")

Get-TimeZone

# on debian/ubuntu timezone should be Etc/UTC on alpine UCT
if ($(Get-TimeZone).Id -ne 'Etc/UTC' -and $(Get-TimeZone).Id -ne 'UCT' -and $(Get-TimeZone).Id -ne 'Zulu' ) {
    throw "TimeZone.Id not equal to Etc/UTC or UCT or Zulu. Value: " + $(Get-TimeZone).Id
}

# Check if gss-ntlmssp is installed
Write-Host("Verifying gss-ntlmssp installation...")
dpkg -s gss-ntlmssp
if ($LASTEXITCODE -ne 0) {
    throw "Verification failed: gss-ntlmssp is not installed."
}

Write-Output("All good. pwsh is setup fine!")
