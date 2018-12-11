FROM python:3.7.1-alpine3.8

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN addgroup -g 4000 demisto \
  && adduser -u 4000 -G demisto -D demisto -s /bin/sh 
