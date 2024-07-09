
FROM demisto/crypto:1.0.0.101635

COPY requirements.txt .

RUN apk --update add --no-cache krb5 krb5-libs
RUN apk --update add --no-cache --virtual .build-dependencies python3-dev libffi-dev gcc build-base wget git \
  openssl-dev krb5-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

