FROM demisto/crypto:1.0.0.107997

COPY requirements.txt .

RUN apk --update add --no-cache libxslt-dev \
  && apk --update add --no-cache --virtual .build-dependencies python3-dev gcc build-base wget git libffi-dev openssl-dev python3-dev libxml2-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies \
  && rm -f -r /usr/include/python3.11.9 \
  && rm -f -r /usr/bin/python3.11.9 \
  && rm -f -r /usr/lib/python3.11.9 \
  && rm -f -r /usr/lib64/python3.11.9 \
  && apt-get update && apt-get install -y --no-install-recommends python3.12 \
  && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1


# Handling the issue described here: https://github.com/ecederstrand/exchangelib/issues/608
# by activating the legacy sect in openssl.cnf (re-enableing md4 to hashlib)
RUN cp /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.org \
&& sed -i '/default = default_sect/a legacy = legacy_sect' /etc/ssl/openssl.cnf \
&& echo -e 'activate = 1\n\n[legacy_sect]\nactivate = 1\n' > /tmp/ssl.cnf \
&& sed -i '/\[default_sect\]/r /tmp/ssl.cnf' /etc/ssl/openssl.cnf \
&& sed -i '/# activate = 1/d' /etc/ssl/openssl.cnf \
&& rm /tmp/ssl.cnf \
&& grep 'legacy_sect' /etc/ssl/openssl.cnf