
FROM demisto/python:2.7.18.24398

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python2-dev build-base wget git libxslt-dev libxml2-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
