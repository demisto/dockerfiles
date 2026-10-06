# Last modified: 2026-09-06T01:14:17.062177+00:00

FROM demisto/python3:3.12.14.12776751

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git linux-headers \
  && apk --update add --no-cache libstdc++ \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
