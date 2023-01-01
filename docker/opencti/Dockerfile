# Last modified: 2023-1-01T16:41:23.690212+00:00
FROM demisto/python3:3.10.9.42476

COPY requirements.txt .

RUN apk --update add --no-cache libmagic

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
