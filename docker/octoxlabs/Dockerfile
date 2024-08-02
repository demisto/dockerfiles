# Last modified: 2024-08-02T00:50:10.020580+00:00
FROM demisto/python3:3.11.9.106008

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
