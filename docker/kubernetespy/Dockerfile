
FROM demisto/python3-deb:3.10.14.91136

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
 gcc \
 python3-dev \
 apt-utils \
 && pip install -U pip \
 && pip install --no-cache-dir -r requirements.txt \
 && apt-get purge -y --auto-remove \
 gcc \
 python3-dev \
 apt-utils \
 && rm -rf /var/lib/apt/lists/*
 