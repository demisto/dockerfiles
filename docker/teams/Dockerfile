# Last modified: 2026-09-03T12:48:51.749943+00:00

FROM demisto/crypto:1.0.0.12701738

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
