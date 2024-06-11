# Last modified: 2024-06-09T12:41:26.450894+00:00
FROM demisto/python3:3.10.14.97374

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
