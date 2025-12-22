# Last modified: 2025-12-22T20:37:43.373236+00:00

FROM demisto/python3:3.12.12.6387406

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
