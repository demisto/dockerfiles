FROM mcr.microsoft.com/powershell:6.1.3-alpine-3.8

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python python-dev py-pip build-base wget \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN addgroup -g 4000 demisto \
  && adduser -u 4000 -G demisto -D demisto -s /bin/sh 
