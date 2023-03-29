# Last modified: 2023-03-29T12:46:21.034393+00:00
FROM demisto/python3:3.10.10.51930

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
