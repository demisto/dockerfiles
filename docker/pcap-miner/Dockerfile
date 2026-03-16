# Last modified: 2026-03-16T13:17:22.655100+00:00
FROM demisto/python3:3.12.13.7444307

COPY requirements.txt .

RUN apk update && apk upgrade

RUN apk --update add --no-cache libxml2 \
  libxslt \
  tshark \
  libmagic

# Use version 4.4.9 and up -  if v3.22 has this version, this line can be removed (wireshark comes from tshark)
RUN apk upgrade wireshark-common tshark --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community

# Download libssh 0.11.4 source - can be removed
ADD https://gitlab.com/libssh/libssh-mirror/-/archive/libssh-0.11.4/libssh-mirror-libssh-0.11.4.tar.gz /tmp/libssh-0.11.4.tar.gz
RUN apk add --no-cache --virtual .libssh-build-deps cmake make gcc g++ openssl-dev zlib-dev \
  && cd /tmp \
  && tar xzf libssh-0.11.4.tar.gz \
  && cd libssh-mirror-libssh-0.11.4 \
  && mkdir build && cd build \
  && cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release -DWITH_EXAMPLES=OFF .. \
  && make -j$(nproc) \
  && make install \
  && cd / \
  && rm -rf /tmp/libssh-mirror-libssh-0.11.4 /tmp/libssh-0.11.4.tar.gz \
  && apk del .libssh-build-deps

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libxml2-dev \
  libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
