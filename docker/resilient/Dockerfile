# Last modified: 2026-09-07T20:40:13.208826+00:00

FROM demisto/python3:3.12.14.12844876

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git  musl-dev openssl-dev libffi-dev  \
  && pip install --no-cache-dir --use-pep517 -r requirements.txt \
  && apk del .build-dependencies
