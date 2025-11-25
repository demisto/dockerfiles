
FROM demisto/python3-deb:3.12.12.5919128

# END Docker file from https://raw.githubusercontent.com/docker-library/python/331890ef059fae05f84c652520b78c340526dc71/3.10/bullseye/Dockerfile

# Basic linux utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
  procps \
&& rm -rf /var/lib/apt/lists/*

# Upgrade all packages to latest
RUN apt-get update && apt-get -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

#RUN rm CVE-2021-3177.diff
COPY requirements.txt .

#Install tools for building binary deps (will be reomved later on)
RUN apt-get update && apt-get install -y -f --no-install-recommends \
    gcc \
    python3-dev \
    build-essential \
    wget \
    git \
    libxml2 \
    libxslt1.1 \
	libkrb5-3 \
    libffi-dev \
    libxml2-dev \
    libxslt-dev \
    libssl-dev \
&& apt-get install -y -f --no-install-recommends --allow-downgrades \
    libcom-err2=1.47.0-2+b2 \
    comerr-dev \
    libkrb5-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  build-essential \
  git \
  wget \
  libffi-dev \
  wget \
  libxml2-dev \
  libssl-dev \
  libkrb5-dev \
&& rm -rf /var/lib/apt/lists/*
