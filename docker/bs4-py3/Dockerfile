FROM demisto/python3:3.10.4.28442

RUN apk --update add --no-cache --virtual .build-dependencies  python3-dev libxml2-dev libxslt-dev build-base wget git \
  && pip install --no-cache-dir xmltodict beautifulsoup4 \
  && apk del .build-dependencies