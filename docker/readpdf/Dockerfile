# Last modified: 2025-09-14T10:47:24.913+00:00

FROM demisto/python3-deb:3.12.11.4801753

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends poppler-utils python3-dev make gcc g++ && \
    pip install --no-cache-dir -r requirements.txt && \
    apt-get purge -y --auto-remove python3-dev make gcc g++ && \
    rm -rf /var/lib/apt/lists/*