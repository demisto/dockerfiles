# Last modified: 2026-05-13T04:43:27.036468+00:00

FROM demisto/btfl-soup:1.0.1.8931184

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
