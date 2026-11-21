# Last modified: 2026-11-01T11:15:00.000000+00:00
FROM node:22.23.4-alpine3.24

# npm, yarn and corepack are not needed at runtime
RUN rm -rf /usr/local/lib/node_modules /opt/yarn-* \
  /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg

# Non-root demisto user like the other demisto images
RUN addgroup -g 4000 demisto \
  && adduser -u 4000 -G demisto -D demisto -s /bin/sh
