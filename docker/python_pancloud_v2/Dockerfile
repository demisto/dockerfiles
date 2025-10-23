# Last modified: 2025-10-23T10:16:53.878+00:00

FROM demisto/crypto:1.0.0.5490413

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
