FROM demisto/opencv:1.0.0.6911470

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
# Last modified: 2026-01-28T16:05:00.971854+00:00
&& rm -rf /var/lib/apt/lists/*
