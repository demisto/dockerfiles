# Last modified: 2025-09-08T10:37:16.080843+00:00
FROM demisto/python3:3.12.11.4508456

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
