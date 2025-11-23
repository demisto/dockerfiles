
#
FROM demisto/python3-deb:3.12.12.5919128

# Basic linux utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
  procps \
&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

#Install tools for building binary deps (will be removed later on)
RUN apt-get update && apt-get install -y -f --no-install-recommends \
    gcc \
    libcom-err2 \
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
