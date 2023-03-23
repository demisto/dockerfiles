# Last modified: 2023-03-23T20:34:19.700509+00:00
FROM demisto/iputils:1.0.0.51091

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk --update add --no-cache curl bind-tools openssl
