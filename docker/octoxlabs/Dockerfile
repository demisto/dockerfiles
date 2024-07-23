# Last modified: 2024-07-23T00:49:29.368214+00:00
FROM demisto/python3:3.11.9.104657

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
