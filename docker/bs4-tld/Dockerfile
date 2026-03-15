# Last modified: 2026-02-11T15:18:34.933506+00:00

FROM demisto/btfl-soup:1.0.1.6977863

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
