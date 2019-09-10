
FROM demisto/python3:3.7.4.1502

COPY requirements.txt .

RUN apk --update add --no-cache openssl

RUN apk --update add --no-cache --virtual .build-dependencies gcc musl-dev python3-dev libffi-dev libressl-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependenciesgc