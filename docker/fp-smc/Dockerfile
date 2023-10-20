# Last modified: 2023-10-20T00:49:57.491503+00:00
FROM demisto/python3:3.10.13.78623

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
