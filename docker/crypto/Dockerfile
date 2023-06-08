
# Note: use this image as a base if you are dependent upon cryptography
# See teams image for an example.
FROM demisto/python3:3.10.12.62631

COPY requirements.txt .

# Crypto  needs the latest pip
RUN pip3 install --no-cache-dir --upgrade pip

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  rust cargo \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies \
  && rm -rf /root/.cargo
