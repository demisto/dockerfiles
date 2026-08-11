
# Last modified: 2026-06-14T04:48:37.982929+00:00

FROM demisto/python3:3.12.13.10116658

RUN mkdir /opt/scripts

COPY scripts /opt/scripts

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev \
  gcc musl-dev linux-headers build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

# Install runtime networking tools from the base image's stable Alpine repo.
# We intentionally do NOT add the rolling `edge` repo: edge is continuously
# rebuilt and old `-rN` package revisions are purged, which caused this build
# to fail with `apk` exit code 2 when pinned versions vanished. The current
# stable base (v3.24/main) already ships curl/libcurl 8.21.0 and sqlite-libs
# 3.53.2, so a floor-pin (>=) on curl/libcurl keeps the security guarantee
# without brittle exact-revision pinning.
RUN apk --update add --no-cache \
  "curl>=8.21.0" \
  "libcurl>=8.21.0" \
  sqlite-libs \
  bind-tools openssl iputils

# Provide a minimal nmap stub so python-libnmap can initialise without the real nmap binary
RUN printf '#!/bin/sh\necho "Nmap stub"\nexit 1\n' \
  > /usr/bin/nmap && chmod +x /usr/bin/nmap
# ---------------------------------------------------------------------------
# TEMPORARY: image-size padding for testing only. DO NOT MERGE TO PRODUCTION.
# Writes ~1.2GB of incompressible random data as a dedicated final layer so
# the total image size is approximately 2GB. Random data is used (instead of
# fallocate/truncate) because sparse/zero-filled files can be stored compactly
# in the image layer and would not reliably grow the image.
# To revert: delete this entire block (the file lives in its own layer).
# ---------------------------------------------------------------------------
RUN dd if=/dev/urandom of=/padding.bin bs=1M count=1200
