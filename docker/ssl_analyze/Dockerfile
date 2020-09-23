
FROM demisto/python3:3.8.5.10845

COPY requirements.txt .

RUN apk add libressl-dev

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git libffi-dev openssl-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
