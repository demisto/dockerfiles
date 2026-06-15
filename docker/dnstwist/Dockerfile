# Last modified: 2026-06-15T04:54:00.371029+00:00

FROM demisto/python3:3.12.13.10116658

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies \
  && wget --no-check-certificate https://github.com/elceef/dnstwist/archive/refs/heads/master.zip \
  && unzip master.zip \
  && mv dnstwist-master dnstwist
