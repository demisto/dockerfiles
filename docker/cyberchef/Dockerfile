# Last modified: 2026-08-26T16:52:04.442001+00:00
FROM demisto/python3:3.12.14.12343672

COPY requirements.txt .
COPY bake.js /bake.js
COPY magic.js /magic.js

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk add --update --no-cache nodejs npm \
  && npm install -g npm@latest

RUN npm install -g --save cyberchef-node \
  && cd /usr/local/lib/node_modules/cyberchef-node \
  && npm install jsonpath-plus@latest \
  && npm cache clean --force \
  && apk del npm \
  && rm -rf /usr/lib/node_modules/npm /usr/bin/npm /usr/bin/npx \
    /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx \
    /root/.npm

ENV NODE_PATH=/usr/local/lib/node_modules
