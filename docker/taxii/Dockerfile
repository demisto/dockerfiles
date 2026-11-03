# Last modified: 2026-11-03T06:14:01.908365+00:00

FROM demisto/btfl-soup:1.0.1.14304551

COPY requirements.txt .

# No libxml2/libxslt packages: the lxml wheel statically links its own.
RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  g++ gcc \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
