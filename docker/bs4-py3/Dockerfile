# Last modified: 2025-10-21T12:45:39.412367+00:00

FROM demisto/python3:3.12.12.5490952

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies  python3-dev libxml2-dev libxslt-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies