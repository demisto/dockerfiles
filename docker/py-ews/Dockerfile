# Last modified: 2026-08-06T05:33:41.893165+00:00

FROM demisto/python3-deb:3.12.13.11694875

# Basic linux utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
  procps \
&& rm -rf /var/lib/apt/lists/*

# Upgrade all packages to latest
RUN apt-get update && apt-get -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

RUN sed -i 's/SECLEVEL=2/SECLEVEL=0/g' /etc/ssl/openssl.cnf

# Handling the issue described here: https://github.com/ecederstrand/exchangelib/issues/608
# NTLM requires MD4 (NT hash = MD4(UTF-16LE(password))). OpenSSL 3.x moved MD4 into the
# legacy provider, and the Debian openssl.cnf ships the provider block commented out, so
# hashlib.new('md4') raises "unsupported hash type md4" (XSUP-76118).
# legacy.so is already present in the image - it only needs to be activated.
RUN cp /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.md4-bak \
&& sed -i 's|^# providers = provider_sect|providers = provider_sect|' /etc/ssl/openssl.cnf \
&& printf '\n[provider_sect]\ndefault = default_sect\nlegacy = legacy_sect\n\n[default_sect]\nactivate = 1\n\n[legacy_sect]\nactivate = 1\n' >> /etc/ssl/openssl.cnf \
&& grep -q '^providers = provider_sect' /etc/ssl/openssl.cnf \
&& grep -q '^\[legacy_sect\]' /etc/ssl/openssl.cnf \
&& openssl list -providers | grep -q 'OpenSSL Legacy Provider'

COPY Pipfile.lock .
COPY Pipfile .

#Install tools for building binary deps (will be removed later on)
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
    libkrb5-dev \
&& pip install --no-cache-dir pipenv \
&& pipenv install --system --deploy \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  build-essential \
  git \
  wget \
  libffi-dev \
  libxml2-dev \
  libssl-dev \
  libkrb5-dev \
&& rm -rf /var/lib/apt/lists/* \
&& pip uninstall -y pipenv
