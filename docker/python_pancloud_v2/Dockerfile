# Last modified: 2026-07-21T01:01:58.126913+00:00

FROM demisto/crypto:1.0.0.11191047

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
