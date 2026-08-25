# Last modified: 2026-08-25T00:43:20.758516+00:00

FROM demisto/python3-deb:3.12.13.12042988

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt cryptography>=50.0.0 \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*
