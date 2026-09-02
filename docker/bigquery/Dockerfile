# Last modified: 2026-07-20T17:02:17.401367+00:00


FROM demisto/python3-deb:3.12.13.11039180

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*

# CIAC-17423 parallel-build POC: touch to include in 30-image parallel test
