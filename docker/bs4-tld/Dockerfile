# Last modified: 2026-03-19T08:00:33.375233+00:00

FROM demisto/btfl-soup:1.0.1.7742802

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
