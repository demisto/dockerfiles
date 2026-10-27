# Last modified: 2026-10-27T06:06:48.190565+00:00
FROM demisto/python3:3.12.15.14069087

COPY requirements.txt .

# This line can be removed once upgrading base image to alpine3.24
RUN echo "https://dl-cdn.alpinelinux.org/alpine/edge/main" >> /etc/apk/repositories \
  && echo "https://dl-cdn.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories \
  && apk --update add --no-cache \
  librdkafka-dev \
  libmagic \
  curl-dev=8.23.0-r0 \
  libcurl=8.23.0-r0

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
