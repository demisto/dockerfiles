# Last modified: 2025-07-16T00:46:24.351306+00:00
FROM demisto/python3:3.12.11.4181428

COPY requirements.txt .

RUN apk --update add --no-cache librdkafka-dev libmagic

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
