# Last modified: 2023-07-19T12:42:38.372656+00:00
FROM demisto/iputils:1.0.0.65900

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk --update add --no-cache curl bind-tools openssl
