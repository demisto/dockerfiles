# Last modified: 2026-08-13T04:46:29.063010+00:00

FROM demisto/python3:3.12.13.11879924

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
