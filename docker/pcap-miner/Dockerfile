# Last modified: 2026-03-18T13:06:45.850759+00:00
FROM demisto/python3:3.12.13.7444307

COPY requirements.txt .

RUN apk update && apk upgrade

RUN apk --update add --no-cache libxml2 \
  libxslt \
  tshark \
  libmagic

# Use version 4.4.9 and up -  if v3.22 has this version, this line can be removed (wireshark comes from tshark)
RUN apk upgrade wireshark-common tshark --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community

RUN apk add --no-cache --virtual .libssh-build-deps ca-certificates cmake samurai openssl-dev zlib-dev build-base \
  && (update-ca-certificates 2>/dev/null || true) \
  && wget -q https://www.libssh.org/files/0.11/libssh-0.11.4.tar.xz -O /tmp/libssh-0.11.4.tar.xz \
  && cd /tmp && tar xf libssh-0.11.4.tar.xz \
  && cd libssh-0.11.4 && mkdir build && cd build \
  && cmake .. -G Ninja -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release -DWITH_EXAMPLES=OFF -DWITH_SERVER=ON \
  && ninja && ninja install \
  && cd / && rm -rf /tmp/libssh-0.11.4* \
  && apk del .libssh-build-deps

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libxml2-dev \
  libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
