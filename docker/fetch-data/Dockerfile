
FROM demisto/python3-deb:3.9.5.21272

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
RUN python -c "import nltk; nltk.download('stopwords', download_dir='/ml/nltk_data'); nltk.download('punkt',download_dir='/ml/nltk_data')"
ENV NLTK_DATA='/ml/nltk_data'

COPY ./glove_50_top_20k.p /ml/glove_50_top_20k.p
COPY ./glove_100_top_20k.p /ml/glove_100_top_20k.p
COPY ./fasttext_top_20k.p /ml/fasttext_top_20k.p
COPY ./domain_to_rank.p /ml/domain_to_rank.p
COPY ./word_to_ngram.p /ml/word_to_ngram.p
COPY ./word_to_regex.p /ml/word_to_regex.p

COPY ./distilledbert-base-uncased /ml/distilledbert-base-uncased
RUN cat /ml/distilledbert-base-uncased/aa.onnx /ml/distilledbert-base-uncased/ab.onnx /ml/distilledbert-base-uncased/ac.onnx /ml/distilledbert-base-uncased/ad.onnx > /ml/distilbert-base-uncased.onnx
RUN rm -r /ml/distilledbert-base-uncased

COPY ./distilled_bert_base_uncased_tokenizer.zip /ml/distilled_bert_base_uncased_tokenizer.zip

RUN apt-get install unzip && unzip /ml/distilled_bert_base_uncased_tokenizer.zip -d /ml && rm /ml/distilled_bert_base_uncased_tokenizer.zip

RUN chown -R demisto:demisto /ml && chmod -R 775 /ml
