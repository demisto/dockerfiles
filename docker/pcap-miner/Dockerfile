# Last modified: 2026-11-08T06:30:59.320029+00:00
FROM demisto/python3:3.12.15.14069087

COPY requirements.txt .

RUN apk update && apk upgrade

# Attempt to install secure versions; if not yet in repos, fallback to available versions
RUN apk --update add --no-cache "libxml2>=2.15.4" "glib>=2.89.0" || true

RUN apk --update add --no-cache libxml2 \
  glib \
  libxslt \
  tshark \
  libmagic

# Upgrade libxml2 from source (2.15.3 not yet in Alpine repos). Remove once base image ships libxml2>=2.15.3.
RUN apk --update add --no-cache "libxml2-dev>=2.15.4" || true

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libxml2-dev \
  libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

# Do not add entries here - this is a workaround used to prevent the wireshark package from being installed in the final image
  RUN sed -i '/^P:tshark$/,/^$/d' /lib/apk/db/installed \
  && sed -i '/^P:wireshark-common$/,/^$/d' /lib/apk/db/installed
