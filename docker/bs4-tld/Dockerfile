# Last modified: 2026-08-27T19:59:45.199044+00:00

FROM demisto/btfl-soup:1.0.1.12408181

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
