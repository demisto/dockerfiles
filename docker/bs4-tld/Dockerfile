# Last modified: 2026-11-23T07:04:57.290708+00:00

FROM demisto/btfl-soup:1.0.1.14606498

COPY requirements.txt .

RUN apk add --no-cache --upgrade openssl libcrypto3 libssl3 krb5 krb5-libs \
  && apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
