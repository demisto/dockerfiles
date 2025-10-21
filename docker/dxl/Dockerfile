# Last modified: 2025-09-10T00:16:10.707788+00:00
FROM demisto/python3:3.12.11.4819260

# Upgrade all packages to latest
RUN apk --update --no-cache upgrade

RUN apk --update add --no-cache --virtual .build-dependencies \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies