# Last modified: 2026-09-01T01:19:18.012820+00:00

FROM demisto/yarapy:1.0.0.12571702

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends python3-dev wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apt-get purge -y --auto-remove python3-dev wget git
