
FROM demisto/python3-deb:3.12.11.4027491

COPY requirements.txt .

# Add tools for troubleshooting
RUN apt-get update && apt-get install -y --no-install-recommends openssl ldap-utils \
  python3-dev wget \
  && pip install --no-cache-dir -r requirements.txt \
  && apt-get purge -y --auto-remove python3-dev wget \
  && rm -rf /var/lib/apt/lists/*
