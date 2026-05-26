# Last modified: 2026-05-20T03:45:05.499144+00:00

FROM demisto/crypto:1.0.0.8931184

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && pip install --no-cache-dir\
  && apk del .build-dependencies
