# Last modified: 2024-07-08T12:44:37.480150+00:00
FROM demisto/python3:3.11.9.101916

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
