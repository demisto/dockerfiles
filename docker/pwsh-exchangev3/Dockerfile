
FROM devdemisto/powershell-ubuntu:7.3.0.62585

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
RUN pwsh -c "Install-Module -Name ExchangeOnlineManagement -RequiredVersion 3.2.0-Preview3 -AllowPrerelease -Scope AllUsers -Force -ErrorAction Stop"
RUN pwsh -c "Install-Module -Name SelfSignedCertificate -Scope AllUsers -Force -ErrorAction Stop"