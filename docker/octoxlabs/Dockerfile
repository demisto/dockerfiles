# Last modified: 2024-09-06T16:40:43.877659+00:00
FROM demisto/python3:3.11.9.109990

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
