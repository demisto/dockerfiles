
FROM demisto/powershell-ubuntu:7.0.3.12001

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
RUN pwsh -c "Install-Module -ErrorAction Stop -Scope AllUsers -Name ExchangeOnlineManagement -RequiredVersion 2.0.4-Preview4 -AllowPrerelease -Force"
