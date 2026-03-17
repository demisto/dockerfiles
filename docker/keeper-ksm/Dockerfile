# Last modified: 2026-03-17T09:02:44.472444+00:00

FROM demisto/crypto:1.0.0.7704170

COPY requirements.txt .

# verify_licenses.py needs the latest pip
RUN pip3 install --no-cache-dir --upgrade pip

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
