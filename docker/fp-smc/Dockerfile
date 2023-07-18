# Last modified: 2023-07-13T00:13:45.597009+00:00
FROM demisto/python3:3.10.12.63474

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
