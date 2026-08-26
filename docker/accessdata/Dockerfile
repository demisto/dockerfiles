# Last modified: 2026-08-26T12:51:17.498171+00:00

FROM demisto/python3:3.12.14.12277297

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies \
  python3-dev \
  build-base \
  git \
&& pip install --no-cache-dir -r requirements.txt \
&& apk del .build-dependencies
