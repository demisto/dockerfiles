# Last modified: 2026-09-08T04:45:19.004158+00:00

FROM demisto/crypto:1.0.0.12833174

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
