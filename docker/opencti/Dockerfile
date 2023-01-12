# Last modified: 2023-01-12T16:49:51.114125+00:00
FROM demisto/python3:3.10.9.43882

COPY requirements.txt .

RUN apk --update add --no-cache libmagic

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
