# Last modified: 2026-01-13T12:13:38.539013+00:00

FROM demisto/python3:3.12.12.6663663

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies  python3-dev libxml2-dev libxslt-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies