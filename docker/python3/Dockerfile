# Last modified: 2026-01-25T13:36:39.650738+00:00
FROM python:3.12.12-alpine3.23

# Upgrade all packages to latest
RUN apk --update --no-cache upgrade

# Fix for XSUP-62124: Add Microsoft TLS G2 ECC certificates to trust store
# Microsoft renewed download.microsoft.com certificate on Jan 13, 2026 with new issuer
# "Microsoft TLS G2 ECC CA OCSP 02" which is not in Alpine 3.23's default CA bundle
# The certificates must be added to both system CA store AND certifi's CA bundle
# because the requests library uses certifi by default
RUN apk --update add --no-cache ca-certificates curl openssl \
  && curl -fsSL -o /tmp/ms-tls-g2-ecc-ca.crt "http://www.microsoft.com/pkiops/certs/Microsoft%20TLS%20G2%20ECC%20CA%20OCSP%2002.crt" \
  && curl -fsSL -o /tmp/ms-tls-ecc-root-g2.crt "http://www.microsoft.com/pkiops/certs/Microsoft%20TLS%20ECC%20Root%20G2.crt" \
  && openssl x509 -inform DER -in /tmp/ms-tls-g2-ecc-ca.crt -out /usr/local/share/ca-certificates/microsoft-tls-g2-ecc-ca-ocsp-02.crt \
  && openssl x509 -inform DER -in /tmp/ms-tls-ecc-root-g2.crt -out /usr/local/share/ca-certificates/microsoft-tls-ecc-root-g2.crt \
  && update-ca-certificates \
  && rm /tmp/ms-tls-g2-ecc-ca.crt /tmp/ms-tls-ecc-root-g2.crt

COPY requirements.txt .

COPY localtime /etc/localtime

# Relevant for tldextract
COPY public_list.dat /var/public_list.dat

RUN apk --update add --no-cache --virtual .build-dependencies \
  python3-dev build-base wget \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies \
  && pip install --upgrade setuptools \
  && pip install --upgrade wheel>=0.46.2

# Fix for XSUP-62124: Update certifi's CA bundle with Microsoft TLS G2 ECC certificates
# The requests library uses certifi's CA bundle, not the system CA certificates
# So we need to append the Microsoft certificates to certifi's cacert.pem file
RUN cat /usr/local/share/ca-certificates/microsoft-tls-g2-ecc-ca-ocsp-02.crt >> $(python3 -c "import certifi; print(certifi.where())") \
  && cat /usr/local/share/ca-certificates/microsoft-tls-ecc-root-g2.crt >> $(python3 -c "import certifi; print(certifi.where())")

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
