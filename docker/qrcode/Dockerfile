
FROM demisto/python3-deb:3.10.13.85666

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
  libzbar0 \
  zbar-tools \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  libzbar0 \
  zbar-tools \
&& rm -rf /var/lib/apt/lists/*
