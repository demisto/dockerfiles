# Last modified: 2026-07-20T17:05:16.910980+00:00

FROM demisto/python3:3.12.13.10404775

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
