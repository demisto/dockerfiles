FROM demisto/python3:3.12.11.4819260


COPY requirements.txt .

RUN apk --update add --no-cache libxml2 \
  libxslt \
  tshark \
  libmagic \
  gnutls \

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libxml2-dev \
  libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
