# Last modified: 2026-03-12T14:47:01.771929+00:00

FROM demisto/python3:3.12.13.7444307

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies \
  python3-dev \
  build-base \
  git \
&& pip install --no-cache-dir -r requirements.txt
