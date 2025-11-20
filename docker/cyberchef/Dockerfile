# Last modified: 2025-11-19T13:12:06.182006+00:00
FROM demisto/python3:3.12.12.5490952

COPY requirements.txt .

RUN apk add --update --no-cache nodejs-lts npm
# can be removed if the default version will be > 11.1.0
RUN npm install -g glob@^11.1.0 --depth 9999

COPY bake.js /bake.js
COPY magic.js /magic.js

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN npm install -g --save cyberchef-node \
  && cd /usr/local/lib/node_modules/cyberchef-node \
  && npm install jsonpath-plus@latest
ENV NODE_PATH=/usr/local/lib/node_modules
