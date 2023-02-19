
FROM demisto/powershell:7.3.0.48974

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
RUN pwsh -c "Install-Module -ErrorAction Stop Az -Scope AllUsers"

