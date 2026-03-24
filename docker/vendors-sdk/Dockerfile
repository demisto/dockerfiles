# Last modified: 2026-03-24T23:44:29.299388+00:00
FROM demisto/python3:3.12.13.7444307

COPY requirements.txt .

RUN apk --update add --no-cache librdkafka-dev libmagic

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
