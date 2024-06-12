# Last modified: 2024-06-07T00:13:56.006206+00:00
FROM python:3.10.14-alpine3.20

# Upgrade all packages to latest
RUN apk --update --no-cache upgrade

COPY requirements.txt .

COPY localtime /etc/localtime

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
