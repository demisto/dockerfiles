# Last modified: 2026-07-29T20:48:26.315798+00:00
FROM demisto/opencv:1.0.0.11446070

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

# CIAC-17423 parallel-build POC: touch to include in parallel capacity test
