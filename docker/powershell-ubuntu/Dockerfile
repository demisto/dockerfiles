# Last modified: Wed, 30 September 2020 16:01:26 +0000
FROM mcr.microsoft.com/powershell:7.1.1-ubuntu-18.04

RUN apt update && apt install netbase -y
# Upgrade all packages to latest
RUN apt-get update && apt-get -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 4000 demisto \
  && useradd --uid 4000 --gid demisto --shell /bin/bash --create-home demisto
