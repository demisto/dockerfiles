# Last modified: Thu, 24 Oct 2019 16:45:04 +0000
FROM python:3.7.5-alpine3.10

# Upgrade all packages to latest
RUN apk --update --no-cache upgrade

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget \  
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN addgroup -g 4000 demisto \
  && adduser -u 4000 -G demisto -D demisto -s /bin/sh 
