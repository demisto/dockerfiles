# Last modified: 2026-05-17T04:58:52.124093+00:00
FROM demisto/python3:3.12.13.9059085

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
  && apk del .build-dependencies
