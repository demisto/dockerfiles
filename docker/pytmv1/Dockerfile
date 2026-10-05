# Last modified: 2026-10-05T04:45:02.498905+00:00

FROM demisto/python3:3.12.14.13495286

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
