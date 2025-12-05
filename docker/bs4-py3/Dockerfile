# Last modified: 2025-12-05T04:41:22.220795+00:00

FROM demisto/python3:3.12.12.6151721

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies  python3-dev libxml2-dev libxslt-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies