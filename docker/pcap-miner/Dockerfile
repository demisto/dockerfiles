FROM demisto/python3:3.12.11.4819260

# Mitigate CVE-2025-32988: ensure latest GnuTLS is installed
RUN apk --update add --no-cache gnutls

COPY requirements.txt .

RUN apk --update add --no-cache libxml2 \
  libxslt \
  tshark \
  libmagic

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libxml2-dev \
  libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
