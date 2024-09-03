# Last modified: 2024-08-28T00:16:29.335948+00:00
FROM python:3.12.5-alpine3.20

# Upgrade all packages to latest
RUN apk --update --no-cache upgrade

COPY requirements.txt .

COPY localtime /etc/localtime

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies \
  && pip install --upgrade setuptools

RUN addgroup -g 4000 demisto \
  && adduser -u 4000 -G demisto -D demisto -s /bin/sh 

# Handling the issue described here https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000POJ0CAO&lang=en_US%E2%80%A9
# by enabling UnsafeLegacyRenegotiation
# We add to the openssl_init section after the last element "providers = provider_sect"
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

# Crypto  needs the latest pip
RUN pip3 install --no-cache-dir --upgrade pip

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  rust cargo \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies \
  && rm -rf /root/.cargo

RUN apk --update add --no-cache libxslt-dev \
  && apk --update add --no-cache --virtual .build-dependencies python3-dev gcc build-base wget git libffi-dev openssl-dev python3-dev libxml2-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
# Handling the issue described here: https://github.com/ecederstrand/exchangelib/issues/608
# by activating the legacy sect in openssl.cnf (re-enableing md4 to hashlib)
RUN cp /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.org \
&& sed -i '/default = default_sect/a legacy = legacy_sect' /etc/ssl/openssl.cnf \
&& echo -e 'activate = 1\n\n[legacy_sect]\nactivate = 1\n' > /tmp/ssl.cnf \
&& sed -i '/\[default_sect\]/r /tmp/ssl.cnf' /etc/ssl/openssl.cnf \
&& sed -i '/# activate = 1/d' /etc/ssl/openssl.cnf \
&& rm /tmp/ssl.cnf \
&& grep 'legacy_sect' /etc/ssl/openssl.cnf