# Last modified: 2026-04-15T09:26:42+03:00
FROM python:3.12.11-slim-bullseye

RUN echo 'deb http://archive.debian.org/debian bullseye-backports main' >> /etc/apt/sources.list

# Basic linux utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
  procps \
&& rm -rf /var/lib/apt/lists/*

# Upgrade all packages to latest
RUN apt-get update && apt-get -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

# Pin OpenSSL packages to patched versions
RUN apt-get update && apt-get install -y --no-install-recommends \
  libssl1.1=1.1.1w-0+deb11u5 \
  openssl=1.1.1w-0+deb11u5 \
&& rm -rf /var/lib/apt/lists/*

# Mitigate glibc iconv vulnerability by removing IBM1390/IBM1399 charsets
RUN rm -f /usr/lib/*/gconv/IBM1390.so /usr/lib/*/gconv/IBM1399.so \
&& iconvconfig

# Upgrade using backports
RUN apt-get update && apt-get -t bullseye-backports -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Relevant for tldextract
COPY --chmod=644 public_list.dat /var/public_list.dat

#Install tools for building binary deps (will be reomved later on)
RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \ 
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/* \
&& pip install --upgrade setuptools

RUN groupadd --gid 4000 demisto \
  && useradd --uid 4000 --gid demisto --shell /bin/bash --create-home demisto
