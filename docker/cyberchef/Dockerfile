# Last modified: 2026-07-27T04:44:18.718308+00:00
FROM demisto/python3:3.12.13.10404775

COPY requirements.txt .
COPY bake.js /bake.js
COPY magic.js /magic.js

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk add --update --no-cache nodejs npm \
  && npm install -g npm@latest brace-expansion@5.0.8 \
  && rm -rf /usr/lib/node_modules/npm /usr/bin/npm /usr/bin/npx

RUN npm install -g --save cyberchef-node \
  && cd /usr/local/lib/node_modules/cyberchef-node \
  && npm install jsonpath-plus@latest

ENV NODE_PATH=/usr/local/lib/node_modules
