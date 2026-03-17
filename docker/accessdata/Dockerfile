# Last modified: 2026-03-16T13:17:22.655100+00:00

FROM demisto/python3:3.12.13.7444307

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies \
  python3-dev \
  build-base \
  git \
&& apk --no-cache upgrade --repository=https://dl-cdn.alpinelinux.org/alpine/edge/main \
  curl libcurl binutils \
&& pip install --no-cache-dir -r requirements.txt
