
FROM demisto/python3:3.9.6.24019

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python2-dev build-base wget \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
