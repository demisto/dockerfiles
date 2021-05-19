# Last modified: Sun, 01 Dec 2019 00:31:13 +0000
FROM demisto/iputils:1.0.0.19143

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk --update add --no-cache curl bind-tools
