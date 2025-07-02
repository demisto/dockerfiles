FROM demisto/python3:3.12.11.3982393

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies \
  python3-dev \
  build-base \
  git \
&& pip install --no-cache-dir -r requirements.txt
