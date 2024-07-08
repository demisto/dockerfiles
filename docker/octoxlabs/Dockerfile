# Last modified: 2024-07-06T04:35:56.715264+00:00
FROM demisto/python3:3.10.14.101217

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
