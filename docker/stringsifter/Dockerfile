
FROM demisto/python3:3.9.5.22665

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev python3-devel python-dev python-devel build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
