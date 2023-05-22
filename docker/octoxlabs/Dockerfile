# Last modified: 2023-05-22T16:37:27.612380+00:00
FROM demisto/python3:3.10.11.60032

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
