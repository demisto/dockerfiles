FROM demisto/python3-deb:3.9.7.24076
RUN apt-get update -y && apt-get -y install build-essential checkinstall cmake wget pkg-config libfontconfig1-dev libjpeg-dev libcairo2-dev libboost-all-dev libopenjp2-7-dev
RUN wget --no-check-certificate poppler.freedesktop.org/poppler-21.10.0.tar.xz -O /tmp/p.tar.xz && \
  tar -xvf /tmp/p.tar.xz -C /tmp && \
  cd /tmp/poppler-21.10.0 && \
  mkdir build && cd build && \
  cmake -DCMAKE_BUILD_TYPE=Release   \
        -DCMAKE_INSTALL_PREFIX=/usr  \
        -DTESTDATADIR=$PWD/testfiles \
        -DENABLE_UNSTABLE_API_ABI_HEADERS=ON \
        .. && \
  make && \
  checkinstall make install && make clean

