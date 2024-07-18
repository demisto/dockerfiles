FROM demisto/python3:3.11.9.103066

COPY requirements.txt .
COPY bake.js /bake.js

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk add --update --no-cache nodejs npm
RUN npm install -g --save cyberchef-node