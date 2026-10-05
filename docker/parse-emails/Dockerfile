# Last modified: 2026-09-14T20:39:44.616856+00:00

FROM demisto/python3:3.12.14.13053055

COPY requirements.txt .

RUN apk --update add --no-cache libmagic

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base libffi-dev wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && pip uninstall -y pcodedmp \
  && apk del .build-dependencies \
  && apk add openssl
