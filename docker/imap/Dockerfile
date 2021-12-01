
FROM demisto/python3:3.9.6.24019

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && git config --global http.sslVerify false && pip install --trusted-host github.com --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
