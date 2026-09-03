# Last modified: 2026-09-03T12:49:11.813535+00:00

FROM demisto/btfl-soup:1.0.1.12689358

COPY requirements.txt .

RUN apk add --update --no-cache libxslt libxml2

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  g++ gcc libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
