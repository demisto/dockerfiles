# Last modified: 2026-07-20T17:06:10.749105+00:00

FROM demisto/btfl-soup:1.0.1.10652093

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
