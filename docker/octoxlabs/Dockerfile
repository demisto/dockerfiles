# Last modified: 2023-05-04T00:50:02.179465+00:00
FROM demisto/python3:3.10.11.56857

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
