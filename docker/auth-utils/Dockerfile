
FROM demisto/crypto:1.0.0.3984129

COPY requirements.txt .

RUN apk --update add --no-cache krb5 krb5-libs openssl-dev openssl
RUN apk --update add --no-cache --virtual .build-dependencies python3-dev libffi-dev gcc build-base wget git \
  krb5-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

