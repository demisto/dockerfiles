# Last modified: 2023-05-19T16:37:21.932257+00:00
FROM demisto/python3:3.10.11.59581

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
