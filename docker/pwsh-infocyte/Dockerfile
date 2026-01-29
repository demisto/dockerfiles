# Last modified: 2026-01-29T13:35:00.210+00:00

FROM demisto/powershell:7.5.0.6911470

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
RUN pwsh -c "Install-Module -ErrorAction Stop InfocyteHUNTAPI -Scope AllUsers"
