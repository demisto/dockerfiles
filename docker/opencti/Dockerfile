# Last modified: 2023-03-20T14:47:35.634436+00:00
FROM demisto/python3:3.10.10.49934

COPY requirements.txt .

RUN apk --update add --no-cache libmagic

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
