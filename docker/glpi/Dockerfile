# Last modified: 2026-09-07T20:41:12.245680+00:00

FROM demisto/python3:3.12.14.12844876

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git musl-dev libffi-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
