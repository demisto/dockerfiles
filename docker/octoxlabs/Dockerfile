# Last modified: 2024-09-10T00:50:56.365850+00:00
FROM demisto/python3:3.11.10.110725

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
