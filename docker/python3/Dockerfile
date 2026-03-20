# Last modified: 2026-03-05T00:29:50.298621+00:00
FROM python:3.12.13-alpine3.23

# Upgrade all packages to latest
RUN apk --update --no-cache upgrade

COPY requirements.txt .

COPY --chmod=644 localtime /etc/localtime

# Relevant for tldextract
COPY --chmod=644 public_list.dat /var/public_list.dat

RUN apk --update add --no-cache --virtual .build-dependencies \
  python3-dev build-base wget \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies \
  && pip install --upgrade setuptools \
  && pip install --upgrade wheel>=0.46.2

RUN addgroup -g 5000 cortex-content \
  && adduser -u 5000 -G cortex-content -D cortex-content -s /bin/sh

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

USER cortex-content
WORKDIR /home/cortex-content
