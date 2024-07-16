
FROM demisto/python3:3.11.9.103066

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk add --update --no-cache nodejs npm git
RUN git init \
  && git remote add origin https://github.com/gchq/CyberChef-server.git \
  && git pull origin v0.0.9 \
  && npm cache clean --force && npm install