# Last modified: Thu, 14 Mar 2019 10:39:33 +0000
FROM python:2.7.16-alpine3.9

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget \  
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN addgroup -g 4000 demisto \
  && adduser -u 4000 -G demisto -D demisto -s /bin/sh 
