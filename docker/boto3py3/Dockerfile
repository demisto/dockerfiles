# Last modified: 2026-10-26T05:51:06.900244+00:00

FROM demisto/python3:3.12.16.14990175

COPY requirements.txt .

RUN apk --update add --no-cache 'openssl>=3.5.9'
RUN apk --update add --no-cache 'krb5-libs>=1.22.3-r0'

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
