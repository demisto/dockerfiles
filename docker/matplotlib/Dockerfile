
FROM demisto/python3:3.10.11.56082

COPY requirements.txt .
COPY requirements-pre.txt .

RUN apk add --update --no-cache  tzdata libxslt freetype jpeg zlib

RUN apk add --no-cache libstdc++ \
  && apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  g++ gcc libxslt-dev freetype-dev jpeg-dev zlib-dev \
  && pip install --no-cache-dir -r requirements-pre.txt \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
