# Last modified: 2025-12-31T04:44:02.583063+00:00
FROM demisto/python3-deb:3.12.12.6493338
# because of this issue we still using 3.11 https://github.com/mandiant/stringsifter/issues/41

COPY requirements.txt .
# The base image demisto/python3-deb:3.12.12.6493338 has bullseye-backports repository configured in its apt sources,
# but this repository is returning a 404 Not Found error because it's no longer available.
RUN sed -i '/bullseye-backports/d' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true \
    && apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends python3-dev  \
    make gcc g++ wget git libgomp1 \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y --auto-remove gcc g++ make python3-dev wget git
