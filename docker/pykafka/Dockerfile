
FROM demisto/python:2.7.17.5426

COPY requirements.txt .

RUN apk --update add --no-cache snappy  

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget snappy-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
