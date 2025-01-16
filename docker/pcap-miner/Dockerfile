# Last modified: 2025-01-16T16:40:10.191035+00:00

FROM demisto/python3:3.11.10.116949

COPY requirements.txt .

RUN apk --update add --no-cache libxml2 \
  libxslt \
  tshark \
  libmagic

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libxml2-dev \
  libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
