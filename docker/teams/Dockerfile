# Last modified: 2026-04-19T09:40:12.317166+00:00

FROM demisto/crypto:1.0.0.7704170

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
