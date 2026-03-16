# Last modified: 2026-03-16T13:17:22.655100+00:00
FROM demisto/python3:3.12.13.7444307

COPY requirements.txt .

RUN apk --update add --no-cache librdkafka-dev libmagic

# upgrade curl to fix use-after-free in SMB request handling
RUN apk --update --no-cache upgrade curl libcurl

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
