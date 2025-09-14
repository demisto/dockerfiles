# Last modified: 2025-09-12T03:11:14.185937+00:00

FROM demisto/python3-deb:3.12.11.4801753

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
  && grep -v "pyobjc" requirements.txt > requirements_filtered.txt \
  && pip install --no-cache-dir -r requirements_filtered.txt \
  && pip uninstall -y pykeepass \
  && apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  && rm -rf /var/lib/apt/lists/*
