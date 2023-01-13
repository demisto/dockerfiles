# Last modified: 2023-01-13T16:45:00.848974+00:00
FROM demisto/python3:3.10.9.44472

COPY requirements.txt .

RUN apk --update add --no-cache libmagic

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
