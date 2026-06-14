# Last modified: 2026-06-14T09:10:32.624021+00:00

FROM demisto/crypto:1.0.0.10120494

COPY requirements.txt .

RUN apk --update add --no-cache libxml2 \
libxslt

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libxml2-dev \
  libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
