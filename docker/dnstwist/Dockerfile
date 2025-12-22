# Last modified: 2025-12-22T20:36:57.642485+00:00

FROM demisto/python3:3.12.12.6387406

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies \
  && wget --no-check-certificate https://github.com/elceef/dnstwist/archive/refs/heads/master.zip \
  && unzip master.zip \
  && mv dnstwist-master dnstwist
