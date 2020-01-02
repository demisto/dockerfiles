FROM demisto/python-deb:2.7.17.4583

COPY requirements.txt .

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
