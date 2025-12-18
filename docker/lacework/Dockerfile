# Last modified: 2025-12-18T14:01:02.238+00:00

FROM demisto/python3:3.12.12.6204436

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
