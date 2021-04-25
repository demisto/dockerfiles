
FROM demisto/powershell-core:7.1.3.18983

COPY requirements.txt .

RUN apk --update add --no-cache libxml2 libxslt
RUN apk --update add --no-cache --virtual .build-dependencies python2-dev build-base wget git libffi-dev libxml2-dev libxslt-dev openssl-dev krb5-dev\
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
