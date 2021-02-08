
FROM demisto/powershell-ubuntu:7.1.1.16151

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
RUN pwsh -c "Install-Module -ErrorAction Stop -Scope AllUsers -Name ExchangeOnlineManagement -RequiredVersion 2.0.4-Preview4 -AllowPrerelease -Force"
RUN pwsh -c "Install-Module -Name SelfSignedCertificate -AllowPrerelease -Force"