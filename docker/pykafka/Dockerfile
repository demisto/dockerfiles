
FROM demisto/python:2.7.17.3066

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
