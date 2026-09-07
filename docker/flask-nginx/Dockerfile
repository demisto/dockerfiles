# Last modified: 2026-09-03T12:49:04.822646+00:00

FROM demisto/crypto:1.0.0.12701738

COPY requirements.txt .

ENV TLDEXTRACT_CACHE="/tldextractcahce"

# Pin musl to 1.2.5 from the Alpine v3.23 repo (XSUP-72663).
RUN echo "https://dl-cdn.alpinelinux.org/alpine/v3.23/main" >> /etc/apk/repositories && \
  apk update && \
  apk add "musl=~1.2.5" "musl-utils=~1.2.5" && \
  apk --update add nginx && \
  nginx -v && \
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