# Last modified: 2026-06-03T13:26:05.161451+00:00

FROM demisto/crypto:1.0.0.8931184

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && pip install --no-cache-dir "urllib3>=2.6.3" \
  && apk del .build-dependencies
