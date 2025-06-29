# Last modified: 2025-06-12T08:51:49.389404+00:00
FROM python:3.9.23-alpine3.22

# Upgrade all packages to latest
RUN apk --update --no-cache upgrade

COPY localtime /etc/localtime

COPY requirements.txt .

# Relevant for tldextract
COPY public_list.dat /var/public_list.dat

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies \
  && pip install --upgrade setuptools

RUN addgroup -g 4000 demisto \
  && adduser -u 4000 -G demisto -D demisto -s /bin/sh

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