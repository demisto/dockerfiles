# Last modified: 2024-05-30T16:35:52.751746+00:00
FROM demisto/python3:3.10.14.96411

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
