FROM demisto/python3:3.8.3.9324

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget git g++ python3-dev\
        openssh curl ca-certificates openssl htop less \
		make  rsync \
        libpng-dev freetype-dev libexecinfo-dev lapack-dev \
        gfortran \
        musl-dev openblas-dev\
  && apk add --no-cache libstdc++  \
  && apk add --no-cache  openblas libgomp \
  && apk add --no-cache bash  \
  && ln -s /usr/include/locale.h /usr/include/xlocale.h \
  && pip3 install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
