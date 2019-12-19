
FROM demisto/python3:3.7.5.4583

COPY requirements.txt .

RUN apk add --no-cache --virtual .build-deps gcc musl-dev \
 && pip install cython \
 && apk del .build-deps
RUN apk add --update --no-cache g++ gcc libxslt-dev freetype-dev jpeg-dev zlib-dev tzdata
RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
