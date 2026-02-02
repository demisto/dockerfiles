# Last modified: 2026-02-02T12:39:34.255601+00:00

FROM demisto/crypto:1.0.0.6932158

COPY requirements.txt .

RUN apk --update add --no-cache libxml2 \
libxslt

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libxml2-dev \
  libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
