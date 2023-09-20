# Last modified: 2023-09-07T16:37:37.988981+00:00
FROM demisto/python3:3.10.13.73190

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
