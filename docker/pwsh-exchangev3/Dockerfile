
FROM demisto/powershell-ubuntu:7.2.2.29705

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
RUN pwsh -c "Install-Module -Name ExchangeOnlineManagement -RequiredVersion 3.0.0 -AllowPrerelease -Scope AllUsers -Force -ErrorAction Stop"
RUN pwsh -c "Install-Module -Name SelfSignedCertificate -Scope AllUsers -Force -ErrorAction Stop"
RUN pwsh -c "Invoke-WebRequest -Uri 'https://github.com/jborean93/omi/releases/download/v1.2.0-pwsh/libmi-centos7.so' -OutFile '/opt/microsoft/powershell/7/libmi.so'"