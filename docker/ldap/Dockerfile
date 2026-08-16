# Last modified: 2026-08-06T05:33:45.746799+00:00

FROM demisto/python3-deb:3.12.13.11694875

COPY requirements.txt .

# Add tools for troubleshooting
RUN apt-get update && apt-get install -y --no-install-recommends openssl ldap-utils \
  python3-dev wget \
  && pip install --no-cache-dir -r requirements.txt \
  && apt-get purge -y --auto-remove python3-dev wget \
  && rm -rf /var/lib/apt/lists/*
