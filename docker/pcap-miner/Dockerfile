# Last modified: 2026-09-24T04:47:42.406878+00:00
FROM demisto/python3:3.12.14.13053055

COPY requirements.txt .

RUN apk update && apk upgrade

RUN apk --update add --no-cache libxml2 \
  libxslt \
  tshark \
  libmagic

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libxml2-dev \
  libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

# Alpine 3.24 (and edge) still ship libxml2 2.13.9-r2, vulnerable to CVE-2026-86138/86139/86140/86142/86143/86144.
# Build 2.15.4 from source and point the old SONAME at it - 2.15.4 keeps every versioned
# symbol tshark/wireshark need, so the .so.2 consumers keep working.
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
  && LD_BIND_NOW=1 tshark -G protocols > /dev/null

# Do not add entries here - this is a workaround used to prevent the wireshark package from being installed in the final image
  RUN sed -i '/^P:tshark$/,/^$/d' /lib/apk/db/installed \
  && sed -i '/^P:wireshark-common$/,/^$/d' /lib/apk/db/installed
