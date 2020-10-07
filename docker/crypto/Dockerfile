
# Note: use this image as a base if you are dependent upon cryptography
# See teams image for an example.
FROM demisto/python3:3.8.5.10455

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
