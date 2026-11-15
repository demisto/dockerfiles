# Last modified: 2026-11-15T05:51:22.370918+00:00

FROM demisto/btfl-soup:1.0.1.14606498

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
