# Last modified: 2025-07-18T04:43:33.503292+00:00
FROM demisto/python3:3.12.11.4208709

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
