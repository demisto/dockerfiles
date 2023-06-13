FROM demisto/python3:3.10.8.37753

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git g++ python3-dev\
        openssh curl ca-certificates openssl less htop \
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

RUN mkdir /ml
RUN python -c "import nltk; nltk.download('wordnet', download_dir='/ml/nltk_data'); nltk.download('stopwords', download_dir='/ml/nltk_data'); nltk.download('punkt', download_dir='/ml/nltk_data')"

ENV NLTK_DATA='/ml/nltk_data'
RUN chown -R demisto:demisto /ml && chmod -R 775 /ml
