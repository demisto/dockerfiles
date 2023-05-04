
FROM demisto/crypto:1.0.0.57519

COPY requirements.txt .

RUN apk --update add --no-cache openssl

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
