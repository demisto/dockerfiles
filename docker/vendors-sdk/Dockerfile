# Last modified: 2026-06-23T04:52:49.564055+00:00
FROM demisto/python3:3.12.13.10381435

COPY requirements.txt .

# This line can be removed once upgrading base image to alpine3.24
RUN echo "https://dl-cdn.alpinelinux.org/alpine/edge/main" >> /etc/apk/repositories \
  && echo "https://dl-cdn.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories \
  && apk --update add --no-cache \
  librdkafka-dev \
  libmagic \
  curl-dev=8.20.0-r1 \
  libcurl=8.20.0-r1

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && pip install --no-cache-dir "cryptography>=48.0.1" "starlette>=1.3.1" \
  && apk del .build-dependencies
