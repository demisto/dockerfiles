# Last modified: 2026-07-21T04:53:00.847644+00:00
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

# ---------------------------------------------------------------------------
# TEMPORARY (padding 1 of 3): image-size padding for testing only.
# DO NOT MERGE TO PRODUCTION.
# ~2GB of incompressible random data written UNDER /ml so it is carried into
# the final image via the `COPY --from=files-src /ml /ml` step below.
# To revert: delete this block.
# ---------------------------------------------------------------------------
RUN dd if=/dev/urandom of=/ml/padding_files_src.bin bs=1M count=2048

FROM demisto/python3-deb:3.12.13.11039180

# ---------------------------------------------------------------------------
# TEMPORARY (padding 2 of 3): image-size padding for testing only.
# DO NOT MERGE TO PRODUCTION.
# ~2GB of incompressible random data as an early dedicated layer in the final
# stage. To revert: delete this block.
# ---------------------------------------------------------------------------
RUN dd if=/dev/urandom of=/padding_final_early.bin bs=1M count=2048

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

# ---------------------------------------------------------------------------
# TEMPORARY (padding 3 of 3): image-size padding for testing only.
# DO NOT MERGE TO PRODUCTION.
# ~2GB of incompressible random data as the final dedicated layer. Combined
# with padding 1 (files-src /ml) and padding 2 (final stage early), this adds
# ~6GB total so the combined image size comfortably exceeds 5GB. Random data
# is used (instead of fallocate/truncate) because sparse/zero-filled files can
# be stored compactly in the image layer and would not reliably grow the image.
# To revert: delete this block (and paddings 1 and 2 above).
# ---------------------------------------------------------------------------
RUN dd if=/dev/urandom of=/padding_final_late.bin bs=1M count=2048
