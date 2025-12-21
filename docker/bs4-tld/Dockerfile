# Last modified: 2025-12-21T10:26:59.431789+00:00

FROM demisto/btfl-soup:1.0.1.6337886

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
