# Last modified: 2026-09-07T12:50:57.966176+00:00

FROM demisto/crypto:1.0.0.12833174

COPY requirements.txt .

RUN apk --update add --no-cache libxml2 \
libxslt

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libxml2-dev \
  libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
