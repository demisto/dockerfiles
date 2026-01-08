# Last modified: 2025-12-23T04:44:28.484628+00:00

FROM demisto/python3:3.12.12.6391686

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies  python3-dev libxml2-dev libxslt-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies