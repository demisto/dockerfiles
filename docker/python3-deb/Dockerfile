# Last modified: 2023-07-05T00:16:00.625130+00:00
FROM docker-infosec.art.code.pan.run/secure-base-image-debian:latest-python310

RUN echo 'deb http://deb.debian.org/debian bullseye-backports main' >> /etc/apt/sources.list

# Basic linux utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
  procps \
&& rm -rf /var/lib/apt/lists/*

# Upgrade all packages to latest
RUN apt-get update && apt-get -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

# Upgrade using backports
RUN apt-get update && apt-get -t bullseye-backports -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

#Install tools for building binary deps (will be reomved later on)
RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \ 
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 4000 demisto \
  && useradd --uid 4000 --gid demisto --shell /bin/bash --create-home demisto

RUN cp /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.org && \
echo -e 'ssl_conf = ssl_sect\n\
[ssl_sect]\n\
system_default = system_default_sect\n\
\n\
[system_default_sect]\n\
Options = UnsafeLegacyRenegotiation\n' > /tmp/ssl.cnf \
&& sed -i '/providers = provider_sect/r /tmp/ssl.cnf' /etc/ssl/openssl.cnf \
&& rm /tmp/ssl.cnf \
&& grep -C 10 'Options = UnsafeLegacyRenegotiation' /etc/ssl/openssl.cnf