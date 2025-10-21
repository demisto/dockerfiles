# Last modified: 2025-09-14T20:26:12.067+00:00

FROM demisto/python3:3.12.11.4819260

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
