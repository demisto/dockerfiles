# Last modified: 2026-01-27T11:27:25.954+00:00

FROM demisto/python3:3.12.12.6875480

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
