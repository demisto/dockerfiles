# Last modified: 2026-11-22T22:17:59.732838+00:00
FROM demisto/python3:3.12.15.14069087

RUN apk add --upgrade --no-cache openssl krb5 krb5-libs

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
