# Last modified: 2026-04-09T07:56:07.999309+00:00

FROM demisto/python3:3.12.13.7444307

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
