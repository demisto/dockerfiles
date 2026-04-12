# Last modified: 2026-04-12T08:19:31.369898+00:00
FROM demisto/python3:3.12.13.8160132

COPY requirements.txt .
COPY bake.js /bake.js
COPY magic.js /magic.js

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk add --update --no-cache nodejs npm \
  && cd /usr/lib/node_modules/npm/node_modules/tar \
  && npm install tar@7.5.11 --prefix /usr/lib/node_modules/npm/node_modules/tar --no-save 2>/dev/null; \
  cp -rf /usr/lib/node_modules/npm/node_modules/tar/node_modules/tar/* /usr/lib/node_modules/npm/node_modules/tar/ 2>/dev/null; \
  rm -rf /usr/lib/node_modules/npm/node_modules/tar/node_modules
RUN npm install -g --save cyberchef-node \
  && cd /usr/local/lib/node_modules/cyberchef-node \
  && npm install jsonpath-plus@latest
ENV NODE_PATH=/usr/local/lib/node_modules
