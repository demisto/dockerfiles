FROM demisto/python3:3.9.8.24399

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies \
  python3-dev \
  build-base \
  wget \
  git \
&& pip install --no-cache-dir -r requirements.txt
RUN pip install git+https://github.com/AccessDataOps/FTK-API-SDK.git@AccessDataV2
