# Last modified: 2026-08-26T16:53:59.927652+00:00
FROM demisto/python3:3.12.14.12343672

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git g++ python3-dev\
        openssh curl ca-certificates openssl less htop \
		make  rsync \
        libpng-dev freetype-dev lapack-dev \
        gfortran \
        musl-dev openblas-dev\
  && apk add --no-cache libstdc++  \
  && apk add --no-cache  openblas libgomp \
  && apk add --no-cache bash  \
  && ln -s /usr/include/locale.h /usr/include/xlocale.h \
  && pip3 install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN mkdir /ml
# nltk.download() returns False on failure instead of raising, so its result must be
# checked: a transient CDN error must fail the build rather than ship empty corpora.
RUN NLTK_MAX_ATTEMPTS=3; NLTK_RETRY_DELAY_SECONDS=5; \
    for resource in wordnet stopwords punkt_tab; do \
        attempt=1; \
        until python -c "import sys, nltk; sys.exit(0 if nltk.download('$resource', download_dir='/ml/nltk_data') else 1)"; do \
            if [ "$attempt" -ge "$NLTK_MAX_ATTEMPTS" ]; then \
                echo "ERROR: failed to download NLTK resource '$resource' after $NLTK_MAX_ATTEMPTS attempts" >&2; \
                exit 1; \
            fi; \
            attempt=$((attempt + 1)); \
            sleep "$NLTK_RETRY_DELAY_SECONDS"; \
        done; \
    done

ENV NLTK_DATA='/ml/nltk_data'
RUN chown -R demisto:demisto /ml && chmod -R 775 /ml

# set the number of threads for numpy libs
ENV OPENBLAS_NUM_THREADS=1
ENV OMP_NUM_THREADS=4
