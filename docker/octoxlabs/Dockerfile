# Last modified: 2024-06-22T00:49:31.422979+00:00
FROM demisto/python3:3.10.14.99144

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
