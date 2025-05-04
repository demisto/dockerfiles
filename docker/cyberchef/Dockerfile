# Last modified: 2025-05-04T12:47:23.539610+00:00
FROM demisto/python3:3.12.8.3296088

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
