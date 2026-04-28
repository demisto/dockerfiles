# Last modified: 2026-04-26T18:44:50.376392+00:00

FROM demisto/powershell-ubuntu:7.5.0.8425368

USER root

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
RUN pwsh -c "Install-Module -Name ExchangeOnlineManagement -RequiredVersion 2.0.4-Preview4 -AllowPrerelease -Scope AllUsers -Force -ErrorAction Stop"
RUN pwsh -c "Install-Module -Name SelfSignedCertificate -Scope AllUsers -Force -ErrorAction Stop"

ENV DEFAULT_USER="demisto"

USER $DEFAULT_USER
WORKDIR /home/$DEFAULT_USER
