# Last modified: 2026-06-14T04:48:37.982929+00:00

FROM demisto/powershell-ubuntu:7.5.0.10049856

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
RUN pwsh -c "Install-Module -Name ExchangeOnlineManagement -Scope AllUsers -Force -ErrorAction Stop"
RUN pwsh -c "Install-Module -Name SelfSignedCertificate -Scope AllUsers -Force -ErrorAction Stop"