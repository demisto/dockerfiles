# Last modified: 2026-09-17T05:01:17.099150+00:00

FROM demisto/crypto:1.0.0.12833174

COPY requirements.txt .

RUN apk --update add --no-cache libxml2 \
libxslt

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libxml2-dev \
  libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
