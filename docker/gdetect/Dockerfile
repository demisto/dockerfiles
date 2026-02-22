# Last modified: 2026-02-22T15:18:34.933506+00:00

FROM demisto/python3:3.12.12.7090913

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
