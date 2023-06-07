# Last modified: 2023-02-20T00:14:42.634087+00:00
FROM mcr.microsoft.com/powershell:preview-7.4-ubuntu-20.04

# For the `no supported WSMan client library was found` error when using Ubuntu 20+
RUN apt-get update -y
RUN apt install gss-ntlmssp

RUN sh -c "yes | pwsh -Command 'Install-Module -Name PSWSMan'"
RUN pwsh -Command 'Install-WSMan'

RUN apt update && apt install netbase -y
# Upgrade all packages to latest
RUN apt-get update && apt-get -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

# Set timezone to Etc/UTC for backwards comp. See: https://github.com/regebro/tzlocal/issues/101
RUN echo 'Etc/UTC' > /etc/timezone \
&& dpkg-reconfigure --frontend noninteractive tzdata

RUN groupadd --gid 4000 demisto \
  && useradd --uid 4000 --gid demisto --shell /bin/bash --create-home demisto
