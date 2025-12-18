# Last modified: 2025-12-18T14:00:57.343+00:00

FROM demisto/python3:3.12.12.6204436

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

WORKDIR /src/rubrik-polaris-sdk-for-python

RUN python setup.py install

WORKDIR /
