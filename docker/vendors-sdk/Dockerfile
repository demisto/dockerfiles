
FROM demisto/python3:3.11.9.107902

ENV LIBRD_VER=2.5.3
RUN apk add --no-cache --virtual .make-deps bash make wget git gcc g++ && apk add --no-cache musl-dev zlib-dev openssl zstd-dev pkgconfig libc-dev
RUN wget https://github.com/edenhill/librdkafka/archive/v${LIBRD_VER}.tar.gz
RUN tar -xvf v2.5.3.tar.gz && cd librdkafka-${LIBRD_VER} && ./configure --prefix=/usr/local && make && make install && make clean
RUN rm -rf librdkafka-${LIBRD_VER} && rm -rf v${LIBRD_VER}.tar.gz && apk del .make-deps

COPY requirements.txt .
RUN apk --update add --no-cache librdkafka-dev libmagic

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

