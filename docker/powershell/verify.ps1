Write-Host("Verify script is running")
Write-Output("All good. pwsh is setup fine!")

if ($(Get-TimeZone).Id -ne 'Etc/UTC') {
    throw "TimeZone.Id not equal to Etc/UTC. Value: " + $(Get-TimeZone).Id
}
