# Last modified: 2026-06-21T04:52:33.643706+00:00

FROM demisto/python3:3.12.13.10325753

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && pip install --no-cache-dir --no-deps "cryptography>=48.0.1" \
  && apk del .build-dependencies
