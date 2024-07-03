# Last modified: 2024-06-30T06:13:16.776367+00:00
FROM demisto/python3:3.10.14.99865

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
