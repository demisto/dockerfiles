# Last modified: 2026-05-13T04:43:27.036468+00:00

FROM demisto/crypto:1.0.0.8931184

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
