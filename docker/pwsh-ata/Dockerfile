
FROM demisto/powershell:7.5.0.3759715

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
RUN pwsh -c "Install-Module -ErrorAction Stop -Scope AllUsers Advanced-Threat-Analytics"
