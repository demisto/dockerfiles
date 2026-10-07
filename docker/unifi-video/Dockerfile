# Last modified: 2026-10-07T05:01:16.001413+00:00
FROM demisto/opencv:1.0.0.13587997

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
  sqlite3 \
  perl \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*
