
FROM demisto/python3:3.10.12.63474

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git libxslt-dev libxml2-dev libffi-dev openssl-dev\
  && pip install --no-cache-dir -r requirements.txt \
  # Install vsphere SDK because cannot install it with pipenv. See: https://github.com/vmware/vsphere-automation-sdk-python/issues/302
  && pip install git+https://github.com/vmware/vsphere-automation-sdk-python.git@v8.0.0.1 \
  && pip install "cryptography>=39.0.1" \
  # cryptographt added explicitly due to security concern. This is a dependency of vsphere-automation-sdk-python.
  && apk del .build-dependencies