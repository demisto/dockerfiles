
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
RUN apt-get update && apt-get install -y --no-install-recommends \
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
    libkrb5-dev \
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
RUN echo 'openssl_conf = default_conf' | cat - /etc/ssl/openssl.cnf > temp-ssl.cnf \
&& mv temp-ssl.cnf /etc/ssl/openssl.cnf \
&& echo "\n\
[default_conf]\n\ 
ssl_conf = ssl_sect\n\ 
\n\
[ssl_sect]\n\
system_default = system_default_sect\n\
\n\
[system_default_sect]\n\
MinProtocol = TLSv1\n\
CipherString = DEFAULT@SECLEVEL=1\n\
" >> /etc/ssl/openssl.cnf
