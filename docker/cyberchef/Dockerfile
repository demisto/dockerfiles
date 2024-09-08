# Last modified: 2024-09-08T00:49:17.597026+00:00
FROM demisto/python3:3.11.9.110419

COPY requirements.txt .
COPY bake.js /bake.js
COPY magic.js /magic.js

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk add --update --no-cache nodejs npm
RUN npm install -g --save cyberchef-node
ENV NODE_PATH=/usr/local/lib/node_modules
