# Last modified: 2026-04-14T07:55:05.781647+00:00

FROM demisto/btfl-soup:1.0.1.8187750

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
