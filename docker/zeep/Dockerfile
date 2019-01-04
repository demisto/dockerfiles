FROM python:alpine3.7

RUN apk --update add --virtual build-dependencies libffi-dev openssl-dev python-dev py-pip build-base gcc libxml2-dev libxslt-dev

RUN pip install zeep
