
FROM demisto/python:2.7.18.63433

COPY requirements.txt .

RUN apk --update add --no-cache libxml2 \
libxslt

RUN apk --update add --no-cache --virtual .build-dependencies python2-dev build-base wget git \
  libxml2-dev \
  libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
