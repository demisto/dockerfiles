# Last modified: 2023-02-02T16:40:56.822343+00:00
FROM demisto/python3:3.10.9.46807

COPY requirements.txt .

RUN apk --update add --no-cache libmagic

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
