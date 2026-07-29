# Last modified: 2026-07-20T17:03:08.258110+00:00
FROM demisto/python3-deb:3.12.13.11039180

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends poppler-utils python3-dev make gcc g++ && \
    pip install --no-cache-dir -r requirements.txt && \
    apt-get purge -y --auto-remove python3-dev make gcc g++ && \
    rm -rf /var/lib/apt/lists/*