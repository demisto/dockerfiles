FROM demisto/pyjwt3:1.0.0.19327

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir beautifulsoup4 xmltodict\
  && apk del .build-dependencies