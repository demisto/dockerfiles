# Last modified: 2026-11-25T05:52:03.877557+00:00
FROM demisto/opencv:1.0.0.15090810

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
