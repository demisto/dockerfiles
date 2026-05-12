# Last modified: 2026-05-12T04:43:40.954754+00:00

FROM demisto/python3:3.12.13.8927230

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
