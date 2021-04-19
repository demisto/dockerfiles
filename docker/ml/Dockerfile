FROM demisto/python3-deb:3.9.4.18682

COPY requirements.txt .

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
  gcc \
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove gcc \
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev
COPY demisto_ml-0.2.tar.gz .
RUN pip install demisto_ml-0.2.tar.gz
RUN rm -rf /var/lib/apt/lists/*

WORKDIR /ml
RUN useradd -m ml
RUN chown -R ml:ml /ml

USER ml

RUN python -m spacy download en_core_web_sm
RUN python -c "import nltk; nltk.download('stopwords', download_dir='/ml/nltk_data'); nltk.download('punkt',download_dir='/ml/nltk_data')"
ENV NLTK_DATA='/ml/nltk_data'
ENV MPLCONFIGDIR='/ml/matplotlib'
COPY encrypted_model.b /ml
COPY oob_evaluation.txt /ml
