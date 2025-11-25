#
FROM demisto/python3-deb:3.12.12.5919128

# Basic linux utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
  procps \
&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Install ALL dependencies needed for the entire build process
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    build-essential \
    libxml2 \
    libxslt1.1 \
    libkrb5-3 \
    libxslt-dev \
&& rm -rf /var/lib/apt/lists/* \
&& pip install --no-cache-dir -r requirements.txt 

# Clean up build dependencies but keep runtime ones
RUN apt-get purge -y --auto-remove \
  gcc \
  build-essential \
  && rm -rf /var/lib/apt/lists/*
