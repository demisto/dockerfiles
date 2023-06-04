
FROM demisto/crypto:1.0.0.62404

COPY requirements.txt .

ENV TLDEXTRACT_CACHE="/tldextractcahce"

RUN apk --update add nginx && \
  mkdir -p /run/nginx && \
  mkdir -p /var/lib/nginx/tmp/cache && \
  mkdir -p /etc/nginx/ssl && \
  chmod -R 755 /var/lib/nginx && \
  mkdir -p /etc/nginx/conf.d && \
  mkdir -p /etc/nginx/ssl && \
  chown -R nginx:demisto /var/log/nginx /run/nginx /var/lib/nginx/tmp /etc/nginx/conf.d /etc/nginx/ssl && \
  chmod -R 775 /var/log/nginx /run/nginx /var/lib/nginx/tmp /etc/nginx/conf.d /etc/nginx/ssl 

COPY nginx.conf /etc/nginx/.

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git libffi-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies \
  && tldextract --update \
  && chmod -R 777 $TLDEXTRACT_CACHE