# Last modified: 2026-08-06T05:33:44.483322+00:00

FROM demisto/python3-deb:3.12.13.11694875

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
