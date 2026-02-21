# Last modified: 2026-02-11T15:18:34.933506+00:00
FROM demisto/python3:3.12.12.7090913

COPY requirements.txt .
COPY bake.js /bake.js
COPY magic.js /magic.js

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk add --update --no-cache nodejs npm
RUN npm install -g --save cyberchef-node \   
  && cd /usr/local/lib/node_modules/cyberchef-node \
  && npm install jsonpath-plus@latest
ENV NODE_PATH=/usr/local/lib/node_modules
