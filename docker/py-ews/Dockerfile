
FROM demisto/python3-deb:3.10.12.67104

# Basic linux utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
  procps \
&& rm -rf /var/lib/apt/lists/*

# Upgrade all packages to latest
RUN apt-get update && apt-get -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

#Install tools for building binary deps (will be reomved later on)
RUN apt-get update && apt-get install -y --no-install-recommends --allow-downgrades \
    gcc \
    python-dev \
    build-essential \
    wget \
    git \
    libcom-err2=1.46.2-2 \
    libxml2 \
    libxslt1.1 \
	libkrb5-3 \
    libffi-dev \
    libxml2-dev \
    libxslt-dev \
    libssl-dev \
    libkrb5-dev  \
    patch \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python-dev \
  build-essential \
  git \
  wget \
  libffi-dev \
  wget \
  libxml2-dev \
  libssl-dev \
  libkrb5-dev \
&& rm -rf /var/lib/apt/lists/*

# Handling the issue described here https://askubuntu.com/questions/1233186/ubuntu-20-04-how-to-set-lower-ssl-security-level 
# by using TLS v1 to support old exchange servers
RUN sed -i.bak '/MinProtocol = TLSv1\.2/{s/TLSv1\.2/TLSv1/}; /CipherString = DEFAULT@SECLEVEL=2/{s/DEFAULT@SECLEVEL=2/DEFAULT@SECLEVEL=1/}' /etc/ssl/openssl.cnf
