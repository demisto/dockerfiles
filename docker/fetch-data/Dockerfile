FROM alpine:3.12.12 as files-src
RUN mkdir /ml
COPY ./glove_50_top_20k.p /ml/glove_50_top_20k.p
COPY ./glove_100_top_20k.p /ml/glove_100_top_20k.p
COPY ./fasttext_top_20k.p /ml/fasttext_top_20k.p
COPY ./domain_to_rank.p /ml/domain_to_rank.p
COPY ./word_to_ngram.p /ml/word_to_ngram.p
COPY ./word_to_regex.p /ml/word_to_regex.p

COPY ./distilledbert-base-uncased /distilledbert-base-uncased
RUN cat /distilledbert-base-uncased/aa.onnx /distilledbert-base-uncased/ab.onnx /distilledbert-base-uncased/ac.onnx /distilledbert-base-uncased/ad.onnx > /ml/distilbert-base-uncased.onnx
RUN rm -r /distilledbert-base-uncased

COPY ./distilled_bert_base_uncased_tokenizer.zip /distilled_bert_base_uncased_tokenizer.zip
RUN unzip /distilled_bert_base_uncased_tokenizer.zip -d /ml \
  && rm /distilled_bert_base_uncased_tokenizer.zip \
  && chmod -R 775 /ml

FROM demisto/python3-deb:3.9.6.24019

COPY requirements.txt .

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
  gcc bash build-essential git curl ca-certificates python3 python3-pip\
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev \
&& pip3 install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove gcc \
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev \
  build-essential python3-pip

RUN mkdir /ml
RUN python -c "import nltk; nltk.download('stopwords', download_dir='/ml/nltk_data'); nltk.download('punkt',download_dir='/ml/nltk_data')" \
  && chown -R demisto:demisto /ml && chmod -R 775 /ml
ENV NLTK_DATA='/ml/nltk_data'

COPY --from=files-src --chown=demisto:demisto /ml /ml
