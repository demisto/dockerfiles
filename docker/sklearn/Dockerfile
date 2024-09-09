FROM demisto/python3-deb:3.11.9.110010

COPY requirements.txt .

RUN apt update && apt install -y \
    python3-dev build-essential wget git g++ python3-dev \
    openssh-client curl ca-certificates openssl less htop \
    make rsync \
    libpng-dev libfreetype6-dev liblapack-dev libgfortran5 \
    libblas-dev \
  && apt install -y libstdc++6 libopenblas-base \
  && apt install -y bash \
  && ln -s /usr/include/locale.h /usr/include/xlocale.h \
  && pip3 install --no-cache-dir -r requirements.txt \
  && apt autoremove -y

RUN mkdir /ml
RUN python -c "import nltk; nltk.download('wordnet', download_dir='/ml/nltk_data'); nltk.download('stopwords', download_dir='/ml/nltk_data'); nltk.download('punkt', download_dir='/ml/nltk_data')"
ENV NLTK_DATA='/ml/nltk_data'

RUN chown -R demisto:demisto /ml && chmod -R 775 /ml
