
# FROM demisto/python3:3.10.12.63474
FROM demisto/python3-deb:3.10.12.71830

COPY requirements.txt .

# RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
#   && pip install --no-cache-dir -r requirements.txt \
#   && apk del .build-dependencies

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
  wget \
  && pip install --no-cache-dir -r requirements.txt \
  && apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  wget \
  && rm -rf /var/lib/apt/lists/*

# from: https://github.com/Unstructured-IO/unstructured/blob/main/Dockerfile
# otherwise XSOAR will periodically throw an error trying to download this nltk module
RUN python3 -c "import nltk; nltk.download('punkt')" && \
  python3 -c "import nltk; nltk.download('averaged_perceptron_tagger')"
