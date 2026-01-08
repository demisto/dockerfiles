# Last modified: 2025-12-23T04:44:10.514833+00:00

FROM demisto/python3:3.12.12.6391686

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
