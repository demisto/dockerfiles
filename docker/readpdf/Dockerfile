FROM demisto/python3-deb:3.10.4.27798

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends ttf-dejavu libstdc++ openjpeg-tools fontconfig &&\
  apt-get install -y --no-install-recommends wget xz build-base cmake py3-pikepdf cairo-dev \
  fontconfig-dev libjpeg-turbo-dev boost-dev openjpeg-dev cairo libjpeg freetype-dev &&\
  wget https://poppler.freedesktop.org/poppler-21.10.0.tar.xz -O /tmp/p.tar.xz && \
  tar -xvf /tmp/p.tar.xz -C /tmp && \
  export CURR_DIR=`pwd` && \
  cd /tmp/poppler-21.10.0 && \
  mkdir build && cd build && \
  cmake -DCMAKE_BUILD_TYPE=Release   \
        -DCMAKE_INSTALL_PREFIX=/usr  \
        -DTESTDATADIR=$PWD/testfiles \
        -DENABLE_UNSTABLE_API_ABI_HEADERS=ON \
        -DCMAKE_BUILD_TYPE=release \
        .. && \
  make && \
  make install && make clean && \
  cd $CURR_DIR && pip install -r requirements.txt

