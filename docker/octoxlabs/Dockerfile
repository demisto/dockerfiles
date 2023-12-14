# Last modified: 2023-12-11T00:48:56.433559+00:00
FROM demisto/python3:3.10.13.83255

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
