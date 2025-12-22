
FROM demisto/python3-deb:3.12.12.5919128

# Basic linux utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
  procps \
&& rm -rf /var/lib/apt/lists/*

# Upgrade all packages to latest
RUN apt-get update && apt-get -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

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
    libgssapi-krb5-2 \
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

RUN sed -i 's/openssl_conf = openssl_init/openssl_conf = openssl_init\n\n[openssl_init]\nproviders = provider_sect\nssl_conf = ssl_sect\n\n[provider_sect]\ndefault = default_sect\nlegacy = legacy_sect\n\n[default_sect]\nactivate = 1\n\n[legacy_sect]\nactivate = 1\n\n[ssl_sect]\nsystem_default = system_default_sect\n\n[system_default_sect]\nCipherString = DEFAULT@SECLEVEL=1/g' /etc/ssl/openssl.cnf