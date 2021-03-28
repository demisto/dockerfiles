
FROM demisto/python3:3.9.2.17957

COPY requirements.txt .

RUN apk --update add --no-cache swig

RUN apk --update add --no-cache --virtual .build-dependencies gcc musl-dev python3-dev libffi-dev openssl-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
