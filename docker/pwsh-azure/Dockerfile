
FROM demisto/powershell:7.4.6.116823

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
RUN pwsh -c "Install-Module -ErrorAction Stop Az -Scope AllUsers"

