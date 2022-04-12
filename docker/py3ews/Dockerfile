FROM python:3.10.4-alpine3.15

COPY requirements.txt .

RUN pip3 install --no-cache-dir --upgrade pip

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev gcc build-base wget git \
  rust cargo \
  libffi-dev openssl-dev libxslt-dev libxml2-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies \
  && rm -rf /root/.cargo
