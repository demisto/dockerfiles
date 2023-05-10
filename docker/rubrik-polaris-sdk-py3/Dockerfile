FROM demisto/python3:3.10.11.57890


COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

WORKDIR /src/rubrik-polaris-sdk-for-python

RUN python setup.py install

WORKDIR /
