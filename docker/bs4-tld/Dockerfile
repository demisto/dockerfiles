# Last modified: 2026-07-21T01:02:11.346074+00:00

FROM demisto/btfl-soup:1.0.1.11191047

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
