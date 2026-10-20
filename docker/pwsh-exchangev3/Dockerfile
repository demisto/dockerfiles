# Last modified: 2026-10-20T04:44:02.060706+00:00

FROM demisto/powershell-ubuntu:7.5.0.13880591

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
# Pin ExchangeOnlineManagement to 3.9.2 - newer versions have an internal Microsoft
# regression that breaks commands on HTTP 401 responses (XSUP-73321 / XSUP-73181).
RUN pwsh -c "Install-Module -Name ExchangeOnlineManagement -RequiredVersion 3.9.2 -Scope AllUsers -Force -ErrorAction Stop"
RUN pwsh -c "Install-Module -Name SelfSignedCertificate -Scope AllUsers -Force -ErrorAction Stop"
