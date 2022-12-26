# Last modified: 2022-12-08T00:13:10.301105+00:00
FROM python:3.10.9-alpine3.17

# Upgrade all packages to latest
RUN apk --update --no-cache upgrade

COPY requirements.txt .

COPY localtime /etc/localtime

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN addgroup -g 4000 demisto \
  && adduser -u 4000 -G demisto -D demisto -s /bin/sh 

# Handling the issue described here https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000POJ0CAO&lang=en_US%E2%80%A9
# by enabling UnsafeLegacyRenegotiation
RUN sed -iE "s/^openssl_conf = .*/openssl_conf = openssl_init/" $destination_file \
if ! grep -q "openssl_conf = openssl_init" $destination_file; then \
	echo "openssl_conf = openssl_init" >> "$destination_file" \
fi \
if ! grep -qF "[openssl_init]" $destination_file; then \
	echo "[openssl_init]" >> "$destination_file" \
	echo "ssl_conf = ssl_sect" >> "$destination_file" \
fi \
sed -iE "s/^ssl_conf = .*/ssl_conf = ssl_sect/" $destination_file \
if ! grep -qF "[ssl_sect]" $destination_file; then \
	echo "[ssl_sect]" >> "$destination_file" \
	echo "system_default = system_default_sect" >> "$destination_file" \
fi \
sed -iE "s/system_default = .*/system_default = system_default_sect/" $destination_file \
if ! grep -qF "[system_default_sect]" $destination_file; then \
	echo "[system_default_sect]" >> "$destination_file" \
	echo "Options = UnsafeLegacyRenegotiation" >> "$destination_file" \
fi \
sed -iE "s/Options = .*/Options = UnsafeLegacyRenegotiation/" $destination_file