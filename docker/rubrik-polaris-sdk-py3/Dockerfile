# Last modified: 2026-06-01T05:06:25.209833+00:00
FROM demisto/python3:3.12.13.9059085

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

WORKDIR /src/rubrik-polaris-sdk-for-python

RUN python setup.py install

WORKDIR /
