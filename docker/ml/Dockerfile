FROM demisto/python3-deb:3.8.6.14507
COPY requirements.txt .

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
  gcc \
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev \
&& ln -s /usr/include/locale.h /usr/include/xlocale.h \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove gcc \
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev
COPY demisto_ml-0.2.tar.gz .
RUN pip install demisto_ml-0.2.tar.gz
RUN rm -rf /var/lib/apt/lists/*
RUN python -m spacy download en_core_web_sm
RUN python -c "import nltk; nltk.download('wordnet'); nltk.download('stopwords'); nltk.download('punkt')"
COPY encrypted_model.b ./var
COPY oob_evaluation.txt ./var
