
FROM demisto/python3:3.8.5.10455

COPY requirements.txt .

RUN apk --update add --no-cache libxslt-dev \
  && apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git libffi-dev openssl-dev python3-dev libxml2-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
