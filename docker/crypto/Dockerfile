
# Note: use this image as a base if you are dependent upon cryptography
# Make sure to include in your Pipfile: cryptography, cffi. So these dependencies
# will be managed by dependabot and upto date.
# See teams image for an example.
FROM demisto/python3:3.8.3.8715

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
