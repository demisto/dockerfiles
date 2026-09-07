# Last modified: 2026-09-06T01:14:34.836346+00:00

FROM demisto/python3:3.12.14.12776751

COPY requirements.txt .

RUN apk add --no-cache libstdc++ \
  && apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
