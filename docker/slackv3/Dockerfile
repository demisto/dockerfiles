# Last modified: 2026-10-11T04:47:13.200743+00:00

FROM demisto/python3:3.12.14.12776751

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base libffi-dev wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
