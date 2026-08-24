# Last modified: 2026-08-05T06:04:32.325941+00:00

FROM demisto/crypto:1.0.0.11658507

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
