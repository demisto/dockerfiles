# Last modified: 2026-08-26T16:56:11.209577+00:00

FROM demisto/python3-deb:3.12.14.12343672

COPY requirements.txt .

# Add tools for troubleshooting
RUN apt-get update && apt-get install -y --no-install-recommends openssl ldap-utils \
  python3-dev wget \
  && pip install --no-cache-dir -r requirements.txt \
  && apt-get purge -y --auto-remove python3-dev wget \
  && rm -rf /var/lib/apt/lists/*
