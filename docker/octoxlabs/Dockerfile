# Last modified: 2023-02-21T15:14:39.948801+00:00
FROM demisto/python3:3.10.10.48392

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
