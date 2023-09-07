# Last modified: 2023-09-07T20:36:19.689647+00:00
FROM demisto/iputils:1.0.0.73478

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk --update add --no-cache curl bind-tools openssl
