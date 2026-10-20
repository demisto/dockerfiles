# Last modified: 2026-10-20T04:44:02.060706+00:00

FROM demisto/powershell:7.5.0.13862703

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
RUN pwsh -c "Install-Module -ErrorAction Stop InfocyteHUNTAPI -Scope AllUsers"
