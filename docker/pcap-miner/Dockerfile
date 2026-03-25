# Last modified: 2026-03-24T23:44:29.299388+00:00
FROM demisto/python3:3.12.13.7444307

COPY requirements.txt .

RUN apk update && apk upgrade

RUN apk --update add --no-cache libxml2 \
  libxslt \
  tshark \
  libmagic

RUN apk upgrade wireshark-common tshark --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community

RUN apk add --no-cache --virtual .libssh-build-deps cmake make gcc g++ openssl-dev zlib-dev \
  && wget --no-check-certificate -q -O libssh-0.11.4.tar.gz https://gitlab.com/libssh/libssh-mirror/-/archive/libssh-0.11.4/libssh-mirror-libssh-0.11.4.tar.gz \
  && tar xzf libssh-0.11.4.tar.gz \
  && cd libssh-mirror-libssh-0.11.4 \
  && mkdir build && cd build \
  && cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release -DWITH_EXAMPLES=OFF -DWITH_SERVER=ON .. \
  && make -j$(nproc) \
  && make install \
  && cd ../.. \
  && rm -rf libssh-mirror-libssh-0.11.4 libssh-0.11.4.tar.gz \
  && rm -f /usr/lib/libssh.so.4.10.3 \
  && apk del .libssh-build-deps

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  libxml2-dev \
  libxslt-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
