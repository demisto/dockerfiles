FROM demisto/python3-deb:3.10.14.98108

WORKDIR "/app"

SHELL ["/bin/bash", "-c"]

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV NSS_VERSION=3_101_1

# Install necessary packages including build dependencies
RUN apt-get update -y -q && \
    apt-get install -y -q nodejs npm gconf-service \
    libasound2 libatk1.0-0 libatk-bridge2.0-0 \
    libc6 libcairo2 libcups2 libdbus-1-3 \
    libexpat1 libfontconfig1 libgcc1 \
    libgconf-2-4 libgdk-pixbuf2.0-0 \
    libglib2.0-0 libgtk-3-0 libnspr4 \
    libpango-1.0-0 libpangocairo-1.0-0 \
    libstdc++6 libx11-6 libx11-xcb1 libxcb1 \
    libxcomposite1 libxcursor1 libxdamage1 \
    libxext6 libxfixes3 libxi6 libxrandr2 \
    libxrender1 libxss1 libxtst6 \
    ca-certificates fonts-liberation \
    libappindicator1 libnss3 lsb-release \
    xdg-utils git mercurial ninja-build \
    python3-pip autoconf libtool pkg-config make gcc g++ \
    && rm -rf /var/lib/apt/lists/*

# Install gyp-next
RUN python3 -m pip install gyp-next

# Clone and build NSS from source
RUN git clone https://github.com/nss-dev/nss.git && \
    git clone https://github.com/nss-dev/nspr.git && \
    cd nss && \
    git checkout NSS_${NSS_VERSION}_RTM && \
    ./build.sh -o && \
    cp -r dist /app/nss-dist

# Install svgexport globally
RUN npm install -g https://github.com/shakiba/svgexport#4c144c589050c039cbfc83a37d8e6d1f6f35bd27 --unsafe-perm=true

# Copy requirements.txt and install Python dependencies
COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  python3-dev \
  make \
  gcc \
  g++ \
  autoconf \
  libtool \
  pkg-config \
  git \
  mercurial \
  npm \
&& rm -rf /var/lib/apt/lists/* /nss /nspr /app/nss-dist

