# Last modified: 2023-08-27T12:43:21.332281+00:00
FROM demisto/python3:3.10.13.72123

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
