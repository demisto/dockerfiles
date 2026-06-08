# Last modified: 2026-05-06T09:09:00.000000+00:00

FROM demisto/python3:3.12.13.8160132

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
