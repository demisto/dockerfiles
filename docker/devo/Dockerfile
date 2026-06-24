# Last modified: 2026-06-24T04:49:35.532453+00:00

FROM demisto/python3-deb:3.12.13.10404775

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& pip install --no-cache-dir cryptography==48.0.1 \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*
