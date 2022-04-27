
FROM demisto/python3:3.10.4.28442

COPY requirements.txt .

RUN apk --update add --no-cache libmagic

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base libffi-dev openssl-dev wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
