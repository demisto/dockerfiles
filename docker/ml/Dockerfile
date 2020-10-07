FROM demisto/python3-deb:3.8.5.11787

COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends python3-dev g++\
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  g++ \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*
RUN python -m spacy download en_core_web_sm

