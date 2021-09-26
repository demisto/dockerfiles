Write-Host("Verify script is running")

Get-TimeZone

# on debian/ubuntu timezone should be Etc/UTC on alpine UCT
if ($(Get-TimeZone).Id -ne 'Etc/UTC' -and $(Get-TimeZone).Id -ne 'UCT' ) {
    throw "TimeZone.Id not equal to Etc/UTC or UCT. Value: " + $(Get-TimeZone).Id
}

Write-Output("All good. pwsh is setup fine!")
