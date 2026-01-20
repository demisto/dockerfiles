FROM demisto/python3:3.12.12.6796194

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git g++ python3-dev\
        openssh curl ca-certificates openssl less htop \
		make  rsync \
        libpng-dev freetype-dev lapack-dev \
        gfortran \
        musl-dev openblas-dev\
  && apk add --no-cache libstdc++  \
  && apk add --no-cache  openblas libgomp \
  && apk add --no-cache bash  \
  && ln -s /usr/include/locale.h /usr/include/xlocale.h \
  && pip3 install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN mkdir /ml
RUN python -c "import nltk; nltk.download('wordnet', download_dir='/ml/nltk_data'); nltk.download('stopwords', download_dir='/ml/nltk_data'); nltk.download('punkt_tab', download_dir='/ml/nltk_data')"

ENV NLTK_DATA='/ml/nltk_data'
RUN chown -R demisto:demisto /ml && chmod -R 775 /ml

# set the number of threads for numpy libs
ENV OPENBLAS_NUM_THREADS=1
ENV OMP_NUM_THREADS=4
