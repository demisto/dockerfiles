# Last modified: 2024-07-11T00:49:25.113946+00:00
FROM demisto/python3:3.11.9.103066

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
