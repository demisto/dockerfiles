# Last modified: 2026-05-03T07:55:11.364145+00:00
FROM demisto/python3:3.12.13.8428455

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

RUN sed -i '/^P:tshark$/,/^$/d' /lib/apk/db/installed \
  && sed -i '/^P:wireshark-common$/,/^$/d' /lib/apk/db/installed
