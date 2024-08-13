# Last modified: 2024-08-08T16:37:12.086455+00:00
FROM demisto/python3:3.11.9.107902

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
