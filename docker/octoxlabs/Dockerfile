# Last modified: 2023-12-10T08:09:19.740670+00:00
FROM demisto/python3:3.10.13.82980

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
