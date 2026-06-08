# Last modified: 2026-05-13T04:43:27.036468+00:00

FROM demisto/python3:3.12.13.8927230

COPY requirements.txt .

RUN apk add --no-cache libstdc++ \
  && apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
