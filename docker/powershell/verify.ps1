Write-Host("Verify script is running")

Get-TimeZone

if ($(Get-TimeZone).Id -ne 'Etc/UTC') {
    throw "TimeZone.Id not equal to Etc/UTC. Value: " + $(Get-TimeZone).Id
}

Write-Output("All good. pwsh is setup fine!")
