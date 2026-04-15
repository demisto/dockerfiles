# Last modified: 2026-04-12T07:52:26.614+00:00

FROM demisto/m2crypto:1.0.0.6894753

# Upgrade all packages to latest
RUN apk --update --no-cache upgrade

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies build-base linux-headers \
    python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
