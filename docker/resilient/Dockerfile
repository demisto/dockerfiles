
FROM demisto/python:2.7.18.18413

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python2-dev build-base wget git  musl-dev openssl-dev libffi-dev  \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
