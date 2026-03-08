# Last modified: 2026-03-08T02:59:34.745075+00:00

FROM demisto/python3-deb:3.12.13.7425833

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*
