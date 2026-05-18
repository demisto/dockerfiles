# Last modified: 2026-05-03T07:55:11.364145+00:00
FROM demisto/python3:3.12.13.8428455

COPY requirements.txt .

RUN apk update && apk upgrade

RUN apk --update add --no-cache libxml2 \
  libxslt \
  tshark \
  libmagic \
&& apk del --no-cache wireshark-common wireshark 2>/dev/null; true

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libxml2-dev \
  libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
