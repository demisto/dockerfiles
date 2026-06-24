# Last modified: 2026-06-24T04:49:35.532453+00:00

FROM demisto/python3:3.12.13.10404775

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
