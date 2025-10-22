# Last modified: 2025-10-22T00:16:10.707788+00:00
FROM demisto/python3:3.12.11.4819260


COPY requirements.txt .
RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies