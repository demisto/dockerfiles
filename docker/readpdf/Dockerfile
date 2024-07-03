# Use the specified base image
FROM demisto/python3-deb:3.10.14.98108

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV NSS_VERSION=3_101_1

# Copy requirements.txt into the container
COPY requirements.txt .

# Install required dependencies, build NSS, and clean up
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
    git && \
    git clone --depth=1 --branch NSS_${NSS_VERSION}_RTM https://github.com/nss-dev/nss.git && \
    mkdir /nss-build && \
    cd /nss-build && \
    ../nss/build.sh && \
    cd /nss-build && \
    make && \
    make install && \
    pip install --no-cache-dir -r requirements.txt && \
    apt-get purge -y --auto-remove \
    python3-dev \
    make \
    gcc \
    g++ \
    autoconf \
    libtool \
    pkg-config \
    git && \
    rm -rf /var/lib/apt/lists/* /nss /nss-build

# Verify the installation of NSS
RUN /usr/local/bin/nss-config --version

