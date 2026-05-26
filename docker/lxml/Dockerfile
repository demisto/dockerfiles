# Last modified: 2026-05-25T05:05:17.994187+00:00

FROM demisto/python3:3.12.13.9059085

COPY requirements.txt .

RUN apk add --update --no-cache libxslt "libxml2>=2.15.3"

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  g++ gcc libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
