# Last modified: 2026-01-20T16:49:46.474653+00:00

FROM demisto/python3:3.12.12.6796194

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies \
  && wget --no-check-certificate https://github.com/elceef/dnstwist/archive/refs/heads/master.zip \
  && unzip master.zip \
  && mv dnstwist-master dnstwist
