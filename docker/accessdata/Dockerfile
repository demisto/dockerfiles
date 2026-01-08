# Last modified: 2025-12-23T04:44:25.640358+00:00

FROM demisto/python3:3.12.12.6391686

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies \
  python3-dev \
  build-base \
  git \
&& pip install --no-cache-dir -r requirements.txt
