FROM demisto/python3-deb:3.10.14.91136

RUN apt-get update && apt-get install -y --no-install-recommends \
    libxslt-dev \
    python3-dev \
    gcc \
    build-essential \
    wget \
    git \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libkrb5-dev \
    libffi-dev \
    libxml2-dev \
    libxslt-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*
  
RUN pip install --no-cache-dir pipenv && \
  pipenv install --system --deploy --ignore-pipfile



# Handling the issue described here: https://github.com/ecederstrand/exchangelib/issues/608
# by activating the legacy sect in openssl.cnf (re-enableing md4 to hashlib)
RUN cp /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.org \
&& sed -i '/default = default_sect/a legacy = legacy_sect' /etc/ssl/openssl.cnf \
&& echo -e 'activate = 1\n\n[legacy_sect]\nactivate = 1\n' > /tmp/ssl.cnf \
&& sed -i '/\[default_sect\]/r /tmp/ssl.cnf' /etc/ssl/openssl.cnf \
&& sed -i '/# activate = 1/d' /etc/ssl/openssl.cnf \
&& rm /tmp/ssl.cnf \
&& grep 'legacy_sect' /etc/ssl/openssl.cnf