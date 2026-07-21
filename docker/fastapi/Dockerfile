# Last modified: 2026-07-21T09:20:56.438565+00:00

FROM demisto/m2crypto:1.0.0.11195141

# Upgrade all packages to latest
RUN apk --update --no-cache upgrade

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies build-base linux-headers \
    python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
