FROM demisto/python3:3.9.7.24076

RUN apk update && apk add --no-cache alpine-sdk cmake wget xz freetype-dev \
  fontconfig ttf-dejavu libjpeg fontconfig-dev libjpeg-turbo-dev cairo cairo-dev \
  boost-dev openjpeg-tools openjpeg-dev

RUN wget https://poppler.freedesktop.org/poppler-21.10.0.tar.xz -O /tmp/p.tar.xz && \
  tar -xvf /tmp/p.tar.xz -C /tmp && \
  cd /tmp/poppler-21.10.0 && \
  mkdir build && cd build && \
  cmake -DCMAKE_BUILD_TYPE=Release   \
        -DCMAKE_INSTALL_PREFIX=/usr  \
        -DTESTDATADIR=$PWD/testfiles \
        -DENABLE_UNSTABLE_API_ABI_HEADERS=ON \
        .. && \
  make && \
  make install && make clean