# Last modified: 2026-07-26T12:49:51.973386+00:00

FROM demisto/powershell:7.5.0.11326619

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
RUN pwsh -c "Install-Module -ErrorAction Stop InfocyteHUNTAPI -Scope AllUsers"
