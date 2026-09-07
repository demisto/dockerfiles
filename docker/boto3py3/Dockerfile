# Last modified: 2026-09-07T20:39:36.031803+00:00

FROM demisto/python3:3.12.14.12844876

COPY requirements.txt .

RUN apk --update add --no-cache openssl=3.5.8-r0

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
