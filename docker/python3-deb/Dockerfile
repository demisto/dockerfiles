# Last modified: 2025-11-19T00:28:10.669343+00:00
FROM python:3.12.12-slim-bookworm

RUN echo 'deb http://deb.debian.org/debian bookworm-backports main' >> /etc/apt/sources.list

# Basic linux utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
  procps \
&& rm -rf /var/lib/apt/lists/*

# Upgrade all packages to latest
RUN apt-get update && apt-get -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

# Upgrade using backports
RUN apt-get update && apt-get -t bookworm-backports -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

COPY Pipfile Pipfile.lock ./

# Relevant for tldextract
COPY public_list.dat /var/public_list.dat

#Install tools for building binary deps (will be removed later on)
RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& pip install --no-cache-dir pipenv \
&& pipenv install --system --deploy \
&& pip uninstall -y pipenv \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*

# Handling the issue described here https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000POJ0CAO&lang=en_US%E2%80%A9
# by enabling UnsafeLegacyRenegotiation
# Also enabling legacy provider to support MD4 and other legacy hash algorithms
# We add to the openssl_init section after the last element "providers = provider_sect"
RUN cp /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.org && \
echo 'ssl_conf = ssl_sect\n\
[ssl_sect]\n\
system_default = system_default_sect\n\
\n\
[system_default_sect]\n\
Options = UnsafeLegacyRenegotiation\n' > /tmp/ssl.cnf \
&& sed -i '/providers = provider_sect/r /tmp/ssl.cnf' /etc/ssl/openssl.cnf \
&& rm /tmp/ssl.cnf \
&& echo "" >> /etc/ssl/openssl.cnf \
&& echo "[legacy_sect]" >> /etc/ssl/openssl.cnf \
&& echo "activate = 1" >> /etc/ssl/openssl.cnf \
&& sed -i '/\[provider_sect\]/a legacy = legacy_sect' /etc/ssl/openssl.cnf \
&& grep -C 10 'Options = UnsafeLegacyRenegotiation' /etc/ssl/openssl.cnf

RUN groupadd --gid 4000 demisto \
  && useradd --uid 4000 --gid demisto --shell /bin/bash --create-home demisto
