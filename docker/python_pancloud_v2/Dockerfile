# Last modified: 2025-12-21T14:12:04.114+00:00

FROM demisto/crypto:1.0.0.6308375

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
