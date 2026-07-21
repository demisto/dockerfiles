# Last modified: 2026-07-21T05:34:14.290529+00:00

FROM demisto/crypto:1.0.0.11193239

COPY requirements.txt .

# verify_licenses.py needs the latest pip
RUN pip3 install --no-cache-dir --upgrade pip

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
