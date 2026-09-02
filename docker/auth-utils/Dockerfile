# Last modified: 2026-07-21T09:20:51.776329+00:00

FROM demisto/crypto:1.0.0.11200773

COPY requirements.txt .

RUN apk --update add --no-cache krb5 krb5-libs openssl-dev openssl
RUN apk --update add --no-cache --virtual .build-dependencies python3-dev libffi-dev gcc build-base wget git \
  krb5-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies


# CIAC-17423 parallel-build POC: touch to include in 30-image parallel test
