# Last modified: 2026-03-29T07:22:42.411788+00:00

FROM demisto/python3:3.12.13.7444307

RUN mkdir /opt/scripts

COPY scripts /opt/scripts

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev \
  gcc musl-dev linux-headers build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN echo "https://dl-cdn.alpinelinux.org/alpine/edge/main" >> /etc/apk/repositories \
  && apk --update add --no-cache \
  curl=8.19.0-r0 \
  libcurl=8.19.0-r0 \
  bind-tools openssl iputils nmap nmap-scripts tcpdump
