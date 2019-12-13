
FROM demisto/python:2.7.17.4002

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget git \
  && apk add --update --no-cache g++ gcc libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt
