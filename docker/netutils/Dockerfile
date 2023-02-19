# Last modified: 2023-02-16T16:39:29.703800+00:00
FROM demisto/iputils:1.0.0.48844

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk --update add --no-cache curl bind-tools openssl
