# Last modified: 2026-01-15T09:40:12.882+00:00

FROM demisto/python3:3.12.12.6663663

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
