
FROM demisto/powershell:7.0.1.9103

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
RUN pwsh -c "Install-Module -ErrorAction Stop -Scope AllUsers PartnerCenter -RequiredVersion 3.0.10 -Force"
RUN pwsh -c "Install-Module -ErrorAction Stop -Scope AllUsers ExchangeOnlineManagement -RequiredVersion 2.0.4-Preview2 -AllowPrerelease -Force"
