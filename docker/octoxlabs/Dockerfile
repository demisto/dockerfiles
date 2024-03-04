# Last modified: 2024-03-03T12:38:42.558123+00:00
FROM demisto/python3:3.10.13.88772

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
