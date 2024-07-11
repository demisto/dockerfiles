FROM demisto/python3-deb:3.11.9.103065

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends poppler-utils python3-dev make gcc g++ && \
    pip install --no-cache-dir -r requirements.txt && \
    apt-get purge -y --auto-remove python3-dev make gcc g++ && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get remove libnss3 -y && \
    apt update && \
    apt-get install -y -q mercurial ninja-build python3-pip git gyp && \
    python3 -m pip install gyp-next && \
    hg clone https://hg.mozilla.org/projects/nspr && \
    hg clone https://hg.mozilla.org/projects/nss && \
    cd nss && \
    ./build.sh -c -o