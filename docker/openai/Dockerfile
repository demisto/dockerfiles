# FROM demisto/python3:3.10.12.63474
FROM demisto/python3-deb:3.10.12.71830

COPY requirements.txt .

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

# RUN python3 -c "import nltk; nltk.download('punkt')" && \
#   python3 -c "import nltk; nltk.download('averaged_perceptron_tagger')"