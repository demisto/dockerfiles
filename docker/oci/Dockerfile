# Last modified: 2026-08-09T04:48:43.821728+00:00

FROM demisto/python3:3.12.13.11753038

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
