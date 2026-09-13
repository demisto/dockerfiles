# Last modified: 2026-09-13T05:09:36.331279+00:00

FROM demisto/crypto:1.0.0.11658507

RUN apk upgrade --no-cache openssl

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
