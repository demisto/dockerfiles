# Last modified: 2026-09-06T01:13:31.341500+00:00

FROM demisto/python3:3.12.14.12776751

COPY requirements.txt .

RUN apk --update add --no-cache libxml2 libxslt

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget libxml2-dev libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
