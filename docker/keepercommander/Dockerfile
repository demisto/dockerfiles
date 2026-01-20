# Last modified: 2026-01-20T16:48:50.673213+00:00

FROM demisto/python3-deb:3.12.12.6795448

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && pip uninstall -y pykeepass \
  && apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  && rm -rf /var/lib/apt/lists/*
