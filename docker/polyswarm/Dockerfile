# Last modified: 2024-07-04T00:48:43.075888+00:00
FROM demisto/python3:3.10.14.99144

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
