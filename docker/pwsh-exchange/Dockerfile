# Last modified: 2026-07-26T12:49:59.341426+00:00

FROM demisto/powershell-ubuntu:7.5.0.11326619

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
RUN pwsh -c "Install-Module -Name ExchangeOnlineManagement -RequiredVersion 2.0.4-Preview4 -AllowPrerelease -Scope AllUsers -Force -ErrorAction Stop"
RUN pwsh -c "Install-Module -Name SelfSignedCertificate -Scope AllUsers -Force -ErrorAction Stop"
# CIAC-17423 parallel-build POC: touch to include in parallel capacity test
