FROM demisto/python-deb:2.7.18.10627

COPY requirements.txt .

RUN apt-get update && apt-get -t buster-backports install -y --no-install-recommends \
  libicu63 \
  zlib1g \
  && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  g++ \
  python-dev \
  zlib1g-dev \
  libicu-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python-dev \
  g++ \
  zlib1g-dev \
  libicu-dev \
&& rm -rf /var/lib/apt/lists/*
