# Last modified: 2024-05-22T16:36:34.273461+00:00
FROM demisto/python3:3.10.14.95137

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
