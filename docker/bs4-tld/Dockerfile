# Last modified: 2026-10-27T06:06:48.190565+00:00

FROM demisto/btfl-soup:1.0.1.14109060

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
