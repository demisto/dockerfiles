# Last modified: 2026-07-15T04:31:46.211327+00:00

FROM demisto/yarapy:1.0.0.11009641

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends python3-dev wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apt-get purge -y --auto-remove python3-dev wget git

# CIAC-17423 parallel-build POC: touch to include in parallel capacity test
