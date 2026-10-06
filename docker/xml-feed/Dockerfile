# Last modified: 2026-10-04T04:45:53.582232+00:00

FROM demisto/crypto:1.0.0.13447173

RUN apk add --no-cache 'openssl>=3.5.8'

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
