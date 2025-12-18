# Last modified: 2025-12-09T11:21:18.351868+00:00
FROM python:3.12.12-alpine3.23

# Upgrade all packages to latest
RUN apk --update --no-cache upgrade

COPY requirements.txt .

COPY localtime /etc/localtime

# Relevant for tldextract
COPY public_list.dat /var/public_list.dat

RUN apk --update add --no-cache --virtual .build-dependencies \
  python3-dev build-base wget \
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
