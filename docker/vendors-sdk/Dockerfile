# Last modified: 2026-04-12T08:19:31.369898+00:00
FROM demisto/python3:3.12.13.8160132

COPY requirements.txt .

RUN apk --update add --no-cache librdkafka-dev libmagic

RUN echo "https://dl-cdn.alpinelinux.org/alpine/edge/main" >> /etc/apk/repositories \
  && apk --update add --no-cache \
  curl-dev=8.19.0-r0 \
  libcurl=8.19.0-r0

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
