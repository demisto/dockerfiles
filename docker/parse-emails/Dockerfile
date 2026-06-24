# Last modified: 2026-06-24T04:49:35.532453+00:00

FROM demisto/python3:3.12.13.10404775

COPY requirements.txt .

RUN apk --update add --no-cache libmagic

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base libffi-dev wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && pip install --no-cache-dir "cryptography>=48.0.1" \
  && pip uninstall -y pcodedmp \
  && apk del .build-dependencies \
  && apk add openssl
