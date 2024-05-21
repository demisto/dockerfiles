# Last modified: 2024-05-21T16:35:32.003648+00:00
FROM demisto/python3:3.10.14.94490

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
