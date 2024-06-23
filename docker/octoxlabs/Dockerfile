# Last modified: 2024-06-21T00:51:01.610433+00:00
FROM demisto/python3:3.10.14.98889

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
