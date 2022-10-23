
FROM demisto/python3:3.10.8.35482

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git libxslt-dev libxml2-dev libffi-dev openssl-dev\
  && pip install --no-cache-dir -r requirements.txt \
  # Install vsphere SDK because cannot install it with pipenv
  && pip install git+https://github.com/vmware/vsphere-automation-sdk-python.git@v8.0.0.1 \
  && apk del .build-dependencies
