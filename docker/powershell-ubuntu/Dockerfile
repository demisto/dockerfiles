# Last modified: 2026-01-15T16:51:02.583245+00:00
FROM mcr.microsoft.com/powershell:7.5-ubuntu-22.04

# For the `no supported WSMan client library was found` error when using Ubuntu 20+
RUN sh -c "yes | pwsh -Command 'Install-Module -Name PSWSMan'"
RUN pwsh -Command 'Install-WSMan'

# Update, install gss-ntlmssp, upgrade packages, and clean up in a single layer
RUN apt-get update -y && \
    # install wget
    apt-get install -y wget && \
    # install gss-ntlmssp from debian repository
    wget http://ftp.debian.org/debian/pool/main/g/gss-ntlmssp/gss-ntlmssp_1.2.0-1_amd64.deb && \
    dpkg -i gss-ntlmssp_1.2.0-1_amd64.deb && \
    # install any missing dependencies and other required packages
    apt-get install -y --fix-broken netbase tzdata && \
    # clean up the downloaded file
    rm gss-ntlmssp_1.2.0-1_amd64.deb && \
    # upgrade all packages to latest
    apt-get -y --no-install-recommends upgrade && \
    # clean up apt lists
    rm -rf /var/lib/apt/lists/*

# Set timezone to Etc/UTC for backwards comp. See: https://github.com/regebro/tzlocal/issues/101
RUN echo 'Etc/UTC' > /etc/timezone \
&& dpkg-reconfigure --frontend noninteractive tzdata

RUN groupadd --gid 4000 demisto \
  && useradd --uid 4000 --gid demisto --shell /bin/bash --create-home demisto
