# Last modified: 2026-11-15T06:37:32.518786+00:00

FROM demisto/btfl-soup:1.0.1.14606498

COPY requirements.txt .

RUN apk add --no-cache --upgrade krb5 krb5-libs \
  && apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
