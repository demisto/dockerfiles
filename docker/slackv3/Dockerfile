# Last modified: 2026-01-20T16:49:48.786584+00:00

FROM demisto/python3:3.12.12.6796194

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base libffi-dev wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
