# Last modified: 2026-09-07T12:51:04.884323+00:00

FROM demisto/crypto:1.0.0.12833174

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && pip install --no-cache-dir "pyopenssl>=26.0.0" "cryptography>=48.0.1" "urllib3>=2.6.3" \
  && apk del .build-dependencies
