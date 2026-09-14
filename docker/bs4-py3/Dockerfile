# Last modified: 2026-09-14T20:41:26.463307+00:00

FROM demisto/python3:3.12.14.13053055

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies  python3-dev libxml2-dev libxslt-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies