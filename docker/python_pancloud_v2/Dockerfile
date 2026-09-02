# Last modified: 2026-08-20T04:42:14.829609+00:00

FROM demisto/crypto:1.0.0.11658507

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
