# Last modified: 2026-02-02T12:13:59.462+00:00

FROM demisto/python3:3.12.12.6947692

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git linux-headers \
  && apk --update add --no-cache libstdc++ \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
