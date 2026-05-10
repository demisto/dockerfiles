# Last modified: 2026-05-10T07:27:02.042469+00:00

FROM demisto/python3:3.12.13.8428455

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
