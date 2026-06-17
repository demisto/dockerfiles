# Last modified: 2026-06-17T05:09:09.977917+00:00

FROM demisto/python3:3.12.13.10230415

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && pip install --no-cache-dir "cryptography>=48.0.1" \
  && apk del .build-dependencies
