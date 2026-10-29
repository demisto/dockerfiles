# Last modified: 2026-10-29T15:20:00.000000+00:00
FROM node:22.23.4-alpine3.24

# Upgrade all packages to latest (same as demisto/python3)
RUN apk --update --no-cache upgrade

# Content runs scripts only; package managers are not needed at runtime and are a CVE source
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /opt/yarn-* \
  /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg

# Same unprivileged user as the other demisto images
RUN addgroup -g 4000 demisto \
  && adduser -u 4000 -G demisto -D demisto -s /bin/sh
