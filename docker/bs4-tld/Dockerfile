# Last modified: 2026-07-21T05:34:33.389855+00:00

FROM demisto/btfl-soup:1.0.1.11193239

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
