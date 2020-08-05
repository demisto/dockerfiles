FROM demisto/python3:3.7.5.5420
RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget git g++ python3-dev\
        bash openssh curl ca-certificates openssl less htop \
		make  rsync \
        libpng-dev freetype-dev libexecinfo-dev openblas-dev libgomp lapack-dev \
		libgcc libquadmath musl  \
		libgfortran \
        gcc \
        python py-pip  \
        gfortran \
        musl-dev \
  && apk add --no-cache libstdc++  \
  && ln -s /usr/include/locale.h /usr/include/xlocale.h \
  && pip3 install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
