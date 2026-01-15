# Last modified: 2026-01-15T09:40:26.857+00:00

FROM demisto/python3:3.12.12.6663663

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
