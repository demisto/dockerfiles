# Last modified: 2025-09-12T03:11:14.185937+00:00

FROM demisto/python3-deb:3.12.11.4801753

# Basic linux utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
  procps \
&& rm -rf /var/lib/apt/lists/*

# Upgrade all packages to latest
RUN apt-get update && apt-get -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install runtime libraries first
RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2 \
    libxslt1.1 \
    libkrb5-3 \
    libgssapi-krb5-2 \
&& rm -rf /var/lib/apt/lists/*

# Install build dependencies, build packages, then remove build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    build-essential \
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
    libffi-dev \
    libxml2-dev \
    libxslt-dev \
    libssl-dev \
&& rm -rf /var/lib/apt/lists/*
