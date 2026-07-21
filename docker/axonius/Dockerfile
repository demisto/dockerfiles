# Last modified: 2026-07-21T04:53:00.847644+00:00

FROM demisto/crypto:1.0.0.11193239

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && pip install --no-cache-dir "pyopenssl>=26.0.0" "cryptography>=48.0.1" "urllib3>=1.26.21,<2" \
  && apk del .build-dependencies
