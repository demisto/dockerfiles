# Last modified: Wed, 10 Jun 2020 22:06:26 +0000
FROM mcr.microsoft.com/powershell:7.0.1-ubuntu-18.04


# Upgrade all packages to latest
RUN apt-get update && apt-get -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*


RUN groupadd --gid 4000 demisto \
  && useradd --uid 4000 --gid demisto --shell /bin/bash --create-home demisto

RUN pwsh -Command Install-Module -Name ExchangeOnlineManagement -RequiredVersion 2.0.3 -Force
RUN pwsh -Command Install-Module -Name SelfSignedCertificate -Force