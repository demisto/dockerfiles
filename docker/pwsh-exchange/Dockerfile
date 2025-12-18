
FROM demisto/powershell-ubuntu:7.5.0.4903976

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
RUN pwsh -c "Install-Module -Name ExchangeOnlineManagement -RequiredVersion 2.0.4-Preview4 -AllowPrerelease -Scope AllUsers -Force -ErrorAction Stop"
RUN pwsh -c "Install-Module -Name SelfSignedCertificate -Scope AllUsers -Force -ErrorAction Stop"