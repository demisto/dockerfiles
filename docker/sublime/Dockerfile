# Last modified: 2026-08-26T16:52:46.077239+00:00
FROM demisto/python3:3.12.14.12343672

# Upgrade all packages to latest
RUN apk --update --no-cache upgrade

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

