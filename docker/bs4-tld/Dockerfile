# Last modified: 2026-01-28T16:05:00.971854+00:00

FROM demisto/btfl-soup:1.0.1.6894364

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
