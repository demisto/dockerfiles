# Last modified: 2023-12-11T00:13:48.666660+00:00
FROM mcr.microsoft.com/powershell:7.4-debian-bullseye-slim

RUN echo 'deb http://deb.debian.org/debian buster-backports main' >> /etc/apt/sources.list

# Basic linux utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
  procps \
&& rm -rf /var/lib/apt/lists/*

# Upgrade all packages to latest
RUN apt-get update && apt-get -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

# Upgrade using backports
RUN apt-get update && apt-get -t buster-backports -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 4000 demisto \
  && useradd --uid 4000 --gid demisto --shell /bin/bash --create-home demisto
