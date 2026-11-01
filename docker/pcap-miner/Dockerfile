# Last modified: 2026-11-01T06:36:46.296312+00:00
FROM demisto/python3:3.12.15.14069087

COPY requirements.txt .

RUN apk update && apk upgrade

RUN apk --update add --no-cache \
  --repository=http://dl-cdn.alpinelinux.org/alpine/edge/main \
  --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community \
  "libxml2>=2.15.4" \
  "glib>=2.89.0" \
  libxslt \
  tshark \
  libmagic

# Upgrade libxml2 from source (2.15.3 not yet in Alpine repos). Remove once base image ships libxml2>=2.15.3.
RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  --repository=http://dl-cdn.alpinelinux.org/alpine/edge/main \
  --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community \
  "libxml2-dev>=2.15.4" \
  libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

# Do not add entries here - this is a workaround used to prevent the wireshark package from being installed in the final image
  RUN sed -i '/^P:tshark$/,/^$/d' /lib/apk/db/installed \
  && sed -i '/^P:wireshark-common$/,/^$/d' /lib/apk/db/installed
