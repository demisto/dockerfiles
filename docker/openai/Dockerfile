
FROM demisto/python3:3.10.12.63474

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

# from: https://github.com/Unstructured-IO/unstructured/blob/main/Dockerfile
# otherwise XSOAR will periodically throw an error trying to download this nltk module
RUN python3 -c "import nltk; nltk.download('punkt')" && \
    python3 -c "import nltk; nltk.download('averaged_perceptron_tagger')"
