# Last modified: 2025-01-19T16:36:34.241934+00:00
FROM demisto/python3:3.12.8.1983910

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
