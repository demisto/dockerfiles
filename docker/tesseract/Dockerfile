
FROM demisto/python3-deb:3.8.6.12176

RUN apt-get update && apt-get -t buster-backports install -y --no-install-recommends \
  tesseract-ocr \
  && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get -t buster-backports install -y --no-install-recommends \
  tesseract-ocr-deu \
  tesseract-ocr-fra \
  tesseract-ocr-heb \
  tesseract-ocr-ita \
  tesseract-ocr-spa \
  tesseract-ocr-rus \
  tesseract-ocr-tur \
  tesseract-ocr-ara \
  tesseract-ocr-chi-sim \
  tesseract-ocr-chi-sim-vert \
  tesseract-ocr-chi-tra \
  tesseract-ocr-chi-tra-vert \
  tesseract-ocr-jpn \
  tesseract-ocr-jpn-vert \
  && tesseract --version \
  && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get -t buster-backports install -y --no-install-recommends \
  imagemagick \
  file \
  && rm -rf /var/lib/apt/lists/*

# Python packages not needed
# COPY requirements.txt .

# RUN apt-get update && apt-get install -y --no-install-recommends \
#   gcc \
#   python3-dev \
# && pip install --no-cache-dir -r requirements.txt \
# && apt-get purge -y --auto-remove \
#   gcc \
#   python3-dev \
# && rm -rf /var/lib/apt/lists/*
