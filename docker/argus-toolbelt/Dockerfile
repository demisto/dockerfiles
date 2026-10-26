# Last modified: 2026-10-26T08:55:15.749210+00:00

FROM demisto/python3:3.12.15.14069087

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
