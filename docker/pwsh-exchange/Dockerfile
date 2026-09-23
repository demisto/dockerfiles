# Last modified: 2026-09-23T10:50:48.258236+00:00

FROM demisto/powershell-ubuntu:7.5.0.13231769

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
RUN pwsh -c "Install-Module -Name ExchangeOnlineManagement -RequiredVersion 2.0.4-Preview4 -AllowPrerelease -Scope AllUsers -Force -ErrorAction Stop"
RUN pwsh -c "Install-Module -Name SelfSignedCertificate -Scope AllUsers -Force -ErrorAction Stop"