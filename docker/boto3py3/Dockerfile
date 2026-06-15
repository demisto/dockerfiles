# Last modified: 2026-06-15T04:54:00.371029+00:00

FROM demisto/python3:3.12.13.10116658

COPY requirements.txt .

RUN apk --update add --no-cache openssl=3.5.7-r0

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
