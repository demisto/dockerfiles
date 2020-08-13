
FROM demisto/crypto:1.0.0.10664

COPY requirements.txt .

RUN apk --update add --no-cache krb5 krb5-libs

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base krb5-dev wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
