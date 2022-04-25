
FROM demisto/powershell:7.2.1.26295

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
RUN pwsh -c "Install-Module -ErrorAction Stop -Scope AllUsers Advanced-Threat-Analytics"
