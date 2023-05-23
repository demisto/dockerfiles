# Last modified: 2023-05-23T12:43:08.285764+00:00
FROM demisto/python3:3.10.11.61265

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
