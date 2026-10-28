# Last modified: 2026-10-28T06:16:02.383844+00:00

FROM demisto/python3:3.12.15.14069087

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
