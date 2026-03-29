# Last modified: 2026-03-29T07:22:42.411788+00:00

FROM demisto/crypto:1.0.0.7704170

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
