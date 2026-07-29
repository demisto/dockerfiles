
# Last modified: 2026-06-14T04:48:37.982929+00:00

FROM demisto/python3:3.12.13.10116658

RUN mkdir /opt/scripts

COPY scripts /opt/scripts

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev \
  gcc musl-dev linux-headers build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN echo "https://dl-cdn.alpinelinux.org/alpine/edge/main" >> /etc/apk/repositories \
  && apk --update add --no-cache \
  curl=8.20.0-r1 \
  libcurl=8.20.0-r1 \
  sqlite-libs=3.53.2-r0 \
  bind-tools openssl iputils

# Provide a minimal nmap stub so python-libnmap can initialise without the real nmap binary
RUN printf '#!/bin/sh\necho "Nmap stub"\nexit 1\n' \
  > /usr/bin/nmap && chmod +x /usr/bin/nmap
