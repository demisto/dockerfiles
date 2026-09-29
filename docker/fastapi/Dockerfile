# Last modified: 2026-09-20T04:44:17.833959+00:00

FROM demisto/m2crypto:1.0.0.13053055

# Upgrade all packages to latest
RUN apk --update --no-cache upgrade

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies build-base linux-headers \
    python3-dev build-base wget git \
  # base image ships an outdated pip; upgrade to the latest release
  && pip install --no-cache-dir --upgrade pip \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
