# Last modified: 2026-07-14T10:20:52.089717+00:00
FROM demisto/opencv:1.0.0.11009641

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
