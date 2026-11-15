# Last modified: 2026-11-15T06:14:35.293731+00:00

FROM demisto/btfl-soup:1.0.1.14606498

RUN apk add --no-cache "krb5>=1.22.3-r0" "krb5-libs>=1.22.3-r0"

COPY requirements.txt .

# No libxml2/libxslt packages: the lxml wheel statically links its own.
RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  g++ gcc \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
