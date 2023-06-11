# Last modified: 2023-06-08T00:49:44.312763+00:00
FROM demisto/python3:3.10.12.62631

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
