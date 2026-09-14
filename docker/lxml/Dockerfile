# Last modified: 2026-09-14T20:40:13.210532+00:00

FROM demisto/python3:3.12.14.13053055

COPY requirements.txt .

RUN apk add --update --no-cache libxslt libxml2

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  g++ gcc libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
