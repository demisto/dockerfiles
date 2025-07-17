# Last modified: 2025-07-17T00:46:29.274735+00:00
FROM demisto/python3:3.12.11.4195034

COPY requirements.txt .

RUN apk --update add --no-cache librdkafka-dev libmagic

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
