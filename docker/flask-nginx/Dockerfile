# Last modified: 2026-06-14T07:15:20.954157+00:00

FROM demisto/crypto:1.0.0.10120494

COPY requirements.txt .

ENV TLDEXTRACT_CACHE="/tldextractcahce"

# XSUP-72663 ISOLATION (Variant A): keep the NEW musl (1.2.6 from the 3.24 base)
# but roll nginx BACK to 1.28.x by pulling it from the Alpine v3.23 repo.
#   nginx = 1.28.3 (OLD)  |  musl = 1.2.6 (NEW)  |  base Alpine = 3.24.1
# If EDL WORKS here -> nginx 1.30 is the cause. If it FAILS -> nginx is NOT the cause.
RUN echo "https://dl-cdn.alpinelinux.org/alpine/v3.23/main" >> /etc/apk/repositories && \
  echo "https://dl-cdn.alpinelinux.org/alpine/v3.23/community" >> /etc/apk/repositories && \
  apk update && \
  apk add "nginx=~1.28" && \
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