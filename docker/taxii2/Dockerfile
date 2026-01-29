# Last modified: 2026-01-29T13:34:37.640+00:00

FROM demisto/yarapy:1.0.0.6911797

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends python3-dev wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apt-get purge -y --auto-remove python3-dev wget git
