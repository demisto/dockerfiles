# Last modified: 2024-02-08T00:49:39.652072+00:00
FROM demisto/python3:3.10.13.87159

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
