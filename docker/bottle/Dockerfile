# Last modified: 2026-08-26T16:53:06.542156+00:00

FROM demisto/python3:3.12.14.12343672

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
