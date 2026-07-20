# Last modified: 2026-07-20T17:06:08.927871+00:00

FROM demisto/btfl-soup:1.0.1.10652093

COPY requirements.txt .

RUN apk add --update --no-cache libxslt libxml2

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  g++ gcc libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
