
FROM demisto/crypto:1.0.0.17856

COPY requirements.txt .

RUN apk --update add nginx && \
  mkdir -p /run/nginx && \
  mkdir -p /var/lib/nginx/tmp/cache && \
  mkdir -p /etc/nginx/ssl && \
  chmod -R 755 /var/lib/nginx && \
  chown -R nginx:demisto /var/log/nginx /run/nginx /var/lib/nginx/tmp /etc/nginx/conf.d /etc/nginx/ssl && \
  chmod -R 775 /var/log/nginx /run/nginx /var/lib/nginx/tmp /etc/nginx/conf.d /etc/nginx/ssl && \
  mv /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default.conf.example

COPY nginx.conf /etc/nginx/.

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
