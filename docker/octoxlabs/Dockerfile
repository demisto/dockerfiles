# Last modified: 2024-11-05T16:38:55.152213+00:00
FROM demisto/python3:3.11.10.115186

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
