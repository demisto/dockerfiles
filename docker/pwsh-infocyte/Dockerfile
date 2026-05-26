# Last modified: 2026-05-17T04:58:52.124093+00:00

FROM demisto/powershell:7.5.0.9017890

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
RUN pwsh -c "Install-Module -ErrorAction Stop InfocyteHUNTAPI -Scope AllUsers"
