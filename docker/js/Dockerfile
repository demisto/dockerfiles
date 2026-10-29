# Last modified: 2026-10-29T09:30:00.000000+00:00
# demisto/python3 is amd64-only, so the node stage must match it
FROM --platform=linux/amd64 node:22-alpine AS node

FROM demisto/python3:3.12.15.14069087

# Node.js 22 runtime (copied from the official image so the version is pinned independently of the Alpine repo)
# libatomic is unused by Node 22/24 but required by Node 26+, so a future version bump won't fail on libatomic.so.1
RUN apk --update add --no-cache libstdc++ libgcc libatomic
COPY --from=node /usr/local/bin/node /usr/local/bin/node
