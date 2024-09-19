# Last modified: 2024-09-18T00:15:23.740254+00:00
FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04

# For the `no supported WSMan client library was found` error when using Ubuntu 20+
RUN apt-get update -y
RUN sh -c "yes | pwsh -Command 'Install-Module -Name PSWSMan'"
RUN pwsh -Command 'Install-WSMan'

RUN apt update && apt install netbase tzdata -y
# Upgrade all packages to latest
RUN apt-get update && apt-get -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

# Set timezone to Etc/UTC for backwards comp. See: https://github.com/regebro/tzlocal/issues/101
RUN echo 'Etc/UTC' > /etc/timezone \
&& dpkg-reconfigure --frontend noninteractive tzdata

RUN groupadd --gid 4000 demisto \
  && useradd --uid 4000 --gid demisto --shell /bin/bash --create-home demisto
