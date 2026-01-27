# Last modified: 2026-01-27T12:16:31.703049+00:00

FROM demisto/python3:3.12.12.6875480

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies \
  python3-dev \
  build-base \
  git \
&& pip install --no-cache-dir -r requirements.txt
