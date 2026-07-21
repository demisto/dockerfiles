# Last modified: 2026-07-21T09:20:47.002038+00:00

FROM demisto/crypto:1.0.0.11200773

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
