FROM demisto/python3:3.9.7.24076

COPY requirements.txt .

RUN apk update && apk add --no-cache ttf-dejavu  libstdc++ openjpeg-tools fontconfig &&\
  apk add --no-cache --virtual .build-dependencies wget xz build-base cmake qpdf-dev cairo-dev \
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
  cd $CURR_DIR && pip install -r requirements.txt && \
  apk del .build-dependencies 
