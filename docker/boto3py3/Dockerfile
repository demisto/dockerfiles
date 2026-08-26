# Last modified: 2026-08-26T12:50:57.101122+00:00

FROM demisto/python3:3.12.14.12277297

COPY requirements.txt .

RUN apk --update add --no-cache openssl=3.5.7-r0

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
