FROM demisto/python3-deb:3.10.14.98108

ENV DEBIAN_FRONTEND=noninteractive
ENV NSS_VERSION=3_101_1

COPY requirements.txt .

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    poppler-utils \
    python3-dev \
    make \
    gcc \
    g++ \
    autoconf \
    libtool \
    pkg-config \
    git \
    mercurial \
    ninja-build \
    python3-pip && \
    python3 -m pip install gyp-next && \
    git clone --depth=1 https://github.com/nss-dev/nss.git && \
    git clone --depth=1 https://github.com/nss-dev/nspr.git && \
    mkdir /nss-build && \
    cd nss && \
    git checkout NSS_${NSS_VERSION}_RTM && \
    ./build.sh -o && \
    cp -r dist /nss-build && \
    cd /nss-build && \
    pip install --no-cache-dir -r /requirements.txt && \
    apt-get purge -y --auto-remove \
    python3-dev \
    make \
    gcc \
    g++ \
    autoconf \
    libtool \
    pkg-config \
    git \
    mercurial && \
    rm -rf /var/lib/apt/lists/* /nss /nss-build
