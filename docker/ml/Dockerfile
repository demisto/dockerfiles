FROM alpine:3.12.3 as files-src
RUN mkdir /ml
COPY ./encrypted_model.b /ml/encrypted_model.b
RUN chmod -R 775 /ml

FROM demisto/python3-deb:3.9.6.22912

COPY requirements.txt .

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
  gcc \
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& pip install torch==1.9.0+cpu -f https://download.pytorch.org/whl/torch_stable.html\
&& apt-get purge -y --auto-remove gcc \
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev
COPY demisto_ml-0.2.tar.gz .
RUN pip install demisto_ml-0.2.tar.gz
RUN rm -rf /var/lib/apt/lists/*
RUN python -m spacy download en_core_web_sm
RUN mkdir /ml
RUN python -c "import nltk; nltk.download('stopwords', download_dir='/ml/nltk_data'); nltk.download('punkt',download_dir='/ml/nltk_data')"
RUN mkdir /usr/local/share/nltk_data \
  && chmod 755 /usr/local/share/nltk_data \
  && python -m nltk.downloader -d /usr/local/share/nltk_data punkt
ENV NLTK_DATA='/ml/nltk_data'
ENV MPLCONFIGDIR='/ml/matplotlib'
COPY oob_evaluation.txt /ml
RUN chown -R demisto:demisto /ml && chmod -R 775 /ml
COPY --from=files-src --chown=demisto:demisto /ml /ml
RUN python -m spacy download fr_core_news_sm
RUN python -m spacy download de_core_news_sm
