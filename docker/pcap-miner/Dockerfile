# Last modified: 2026-05-03T07:55:11.364145+00:00
FROM demisto/python3:3.12.13.8428455

COPY requirements.txt .

RUN apk update && apk upgrade

RUN apk --update add --no-cache libxml2 \
  libxslt \
  tshark \
  libmagic

# Upgrade libxml2 from source (2.15.3 not yet in Alpine repos). Remove once base image ships libxml2>=2.15.3.
RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libxml2-dev \
  libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

# Do not add entries here - this is a workaround used to prevent the wireshark package from being installed in the final image
  RUN sed -i '/^P:tshark$/,/^$/d' /lib/apk/db/installed \
  && sed -i '/^P:wireshark-common$/,/^$/d' /lib/apk/db/installed
