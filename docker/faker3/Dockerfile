# Last modified: 2025-10-23T12:44:56.987941+00:00

FROM demisto/python3:3.12.12.5490952

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
