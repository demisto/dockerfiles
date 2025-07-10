# Last modified: 2025-07-08T12:44:10.256897+00:00
FROM demisto/python3:3.12.11.4095827

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
