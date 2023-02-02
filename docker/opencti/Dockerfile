# Last modified: 2023-01-27T16:40:05.679501+00:00
FROM demisto/python3:3.10.9.46032

COPY requirements.txt .

RUN apk --update add --no-cache libmagic

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
