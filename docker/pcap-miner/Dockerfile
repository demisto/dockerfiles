# Last modified: 2025-12-23T04:43:55.274719+00:00
FROM demisto/python3:3.12.12.6391686

COPY requirements.txt .

RUN apk update && apk upgrade

RUN apk --update add --no-cache libxml2 \
  libxslt \
  tshark \
  libmagic

# Use version 4.4.9 and up -  if v3.22 has this version, this line can be removed (wireshark comes from tshark)
RUN apk upgrade wireshark-common tshark --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libxml2-dev \
  libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
