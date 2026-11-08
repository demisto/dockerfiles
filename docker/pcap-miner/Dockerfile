# Last modified: 2026-11-08T07:15:39.733193+00:00
FROM demisto/python3:3.12.15.14069087

COPY requirements.txt .

RUN apk update && apk upgrade

RUN apk --update add --no-cache --upgrade \
  libxml2 \
  glib \
  libxslt \
  tshark \
  libmagic \
  --repository=http://dl-cdn.alpinelinux.org/alpine/edge/main \
  --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libxml2-dev \
  libxslt-dev \
  --repository=http://dl-cdn.alpinelinux.org/alpine/edge/main \
  --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

# Do not add entries here - this is a workaround used to prevent the wireshark package from being installed in the final image
  RUN sed -i '/^P:tshark$/,/^$/d' /lib/apk/db/installed \
  && sed -i '/^P:wireshark-common$/,/^$/d' /lib/apk/db/installed
