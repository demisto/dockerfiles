# Last modified: 2026-08-05T04:51:08.023163+00:00

# Note: use this image as a base if you are dependent upon cryptography
# See teams image for an example.
FROM demisto/python3:3.12.13.10404775

COPY requirements.txt .

# Crypto  needs the latest pip
RUN pip3 install --no-cache-dir --upgrade pip

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  rust cargo \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies \
  && rm -rf /root/.cargo
