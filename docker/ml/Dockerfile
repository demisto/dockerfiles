FROM alpine:3.17.10 as files-src
RUN mkdir /ml
COPY ./encrypted_model.b /ml/encrypted_model.b

COPY ./distilledbert-base-uncased /distilledbert-base-uncased
RUN cat /distilledbert-base-uncased/aa.onnx /distilledbert-base-uncased/ab.onnx /distilledbert-base-uncased/ac.onnx /distilledbert-base-uncased/ad.onnx > /ml/distilbert-base-uncased.onnx
RUN rm -r /distilledbert-base-uncased

COPY ./distilled_bert_base_uncased_tokenizer.zip /distilled_bert_base_uncased_tokenizer.zip
RUN unzip /distilled_bert_base_uncased_tokenizer.zip -d /ml \
  && rm /distilled_bert_base_uncased_tokenizer.zip \
  && chmod -R 775 /ml

FROM demisto/python3-deb:3.12.11.4027491
COPY requirements.txt .


RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc python3-dev pipenv gfortran wget git g++ pkg-config libhdf5-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && apt-get purge -y --auto-remove \
  gcc python3-dev gfortran wget git g++ pkg-config libhdf5-dev \
  && apt-get upgrade -y \
  && apt-get install -y perl libsqlite3-0


COPY demisto_ml-0.2.tar.gz .
RUN pip install demisto_ml-0.2.tar.gz
RUN rm -rf /var/lib/apt/lists/*
RUN python -m spacy download en_core_web_sm
RUN mkdir -p /ml/nltk_data && chmod -R 777 /ml/nltk_data
RUN python -c "import nltk; nltk.download('punkt_tab', download_dir='/ml/nltk_data'); nltk.download('stopwords', download_dir='/ml/nltk_data')"

COPY oob_evaluation.txt /ml
RUN chown -R demisto:demisto /ml && chmod -R 775 /ml
COPY --from=files-src --chown=demisto:demisto /ml /ml

ENV HF_HOME='/ml/.cache'
ENV NLTK_DATA='/ml/nltk_data'
ENV MPLCONFIGDIR='/ml/matplotlib'
