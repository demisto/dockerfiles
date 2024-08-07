# Last modified: 2024-08-06T00:49:37.517199+00:00
FROM demisto/python3:3.11.9.106968

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
