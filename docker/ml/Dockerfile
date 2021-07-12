FROM alpine:3.12.3 as files-src
RUN mkdir /ml
COPY ./encrypted_model.b /ml/encrypted_model.b
COPY ./oob_evaluation.txt /ml/oob_evaluation.txt
COPY demisto_ml-0.2.tar.gz /ml/demisto_ml-0.2.tar.gz
RUN chmod -R 775 /ml

FROM demisto/python3-deb:3.9.5.21272

COPY requirements.txt .

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
  gcc \
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove gcc \
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev
RUN rm -rf /var/lib/apt/lists/*
RUN python -m spacy download en_core_web_sm
RUN mkdir /ml
RUN python -c "import nltk; nltk.download('stopwords', download_dir='/ml/nltk_data'); nltk.download('punkt',download_dir='/ml/nltk_data')"
ENV NLTK_DATA='/ml/nltk_data'
ENV MPLCONFIGDIR='/ml/matplotlib'
RUN chown -R demisto:demisto /ml && chmod -R 775 /ml
COPY --from=files-src --chown=demisto:demisto /ml /ml
RUN pip install /ml/demisto_ml-0.2.tar.gz
