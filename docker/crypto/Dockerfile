# Last modified: 2026-01-13T12:12:49.292310+00:00

# Note: use this image as a base if you are dependent upon cryptography
# See teams image for an example.
FROM demisto/python3:3.12.12.6663663

COPY requirements.txt .

# Crypto  needs the latest pip
RUN pip3 install --no-cache-dir --upgrade pip

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  rust cargo \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies \
  && rm -rf /root/.cargo
