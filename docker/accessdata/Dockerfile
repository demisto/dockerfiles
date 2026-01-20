# Last modified: 2026-01-20T16:50:50.978698+00:00

FROM demisto/python3:3.12.12.6796194

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies \
  python3-dev \
  build-base \
  git \
&& pip install --no-cache-dir -r requirements.txt
