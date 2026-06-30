# Last modified: 2026-06-28T09:18:35.851553+00:00

FROM demisto/crypto:1.0.0.10120494

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
