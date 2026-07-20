# Last modified: 2026-07-20T20:54:56.342953+00:00

FROM demisto/crypto:1.0.0.11188826

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
