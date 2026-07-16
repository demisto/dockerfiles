# Last modified: 2026-07-14T07:50:42.385524+00:00

FROM demisto/python3-deb:3.12.13.10786156

COPY requirements.txt .

# Add tools for troubleshooting
RUN apt-get update && apt-get install -y --no-install-recommends openssl ldap-utils \
  python3-dev wget \
  && pip install --no-cache-dir -r requirements.txt \
  && apt-get purge -y --auto-remove python3-dev wget \
  && rm -rf /var/lib/apt/lists/*
