
FROM demisto/python3-deb:3.10.14.91136

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git apt-utils \
  && pip install -U pip \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies