# Last modified: 2026-10-27T06:06:48.190565+00:00

FROM demisto/crypto:1.0.0.14109060

RUN apk add --no-cache 'openssl>=3.5.8'

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
