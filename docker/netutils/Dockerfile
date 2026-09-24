# Last modified: 2026-09-24T04:47:42.406878+00:00


FROM demisto/python3:3.12.14.13053055

RUN mkdir /opt/scripts

COPY scripts /opt/scripts

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev \
  gcc musl-dev linux-headers build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN echo "https://dl-cdn.alpinelinux.org/alpine/edge/main" >> /etc/apk/repositories \
  && apk --update add --no-cache \
  curl=8.22.0-r0 \
  libcurl=8.22.0-r0 \
  sqlite-libs=3.53.4-r0 \
  bind-tools openssl iputils

# Alpine 3.24 (and edge) still ship libxml2 2.13.9-r2, vulnerable to CVE-2026-86138/86139/86140/86142/86143/86144.
# bind-tools pulls it in. Build 2.15.4 from source and point the old SONAME at it - 2.15.4 keeps
# every versioned symbol libdns/libisc need, so dig and friends keep working.
# Remove this block once Alpine ships libxml2 >= 2.15.4.
ARG LIBXML2_VERSION=2.15.4
RUN apk --update add --no-cache --virtual .libxml2-build build-base git meson ninja pkgconf \
  && git clone --depth 1 --branch "v${LIBXML2_VERSION}" https://github.com/GNOME/libxml2.git /tmp/libxml2 \
  && cd /tmp/libxml2 \
  && meson setup build --prefix=/usr --libdir=/usr/lib --buildtype=release -Dpython=disabled \
  && ninja -C build \
  && ninja -C build install \
  && rm -f /usr/lib/libxml2.so.2 /usr/lib/libxml2.so.2.13.9 \
  && ln -s libxml2.so.16 /usr/lib/libxml2.so.2 \
  && cd / && rm -rf /tmp/libxml2 \
  && apk del .libxml2-build \
  && sed -i '/^P:libxml2$/,/^$/d' /lib/apk/db/installed \
  && LD_BIND_NOW=1 dig -v

# Provide a minimal nmap stub so python-libnmap can initialise without the real nmap binary
RUN printf '#!/bin/sh\necho "Nmap stub"\nexit 1\n' \
  > /usr/bin/nmap && chmod +x /usr/bin/nmap
