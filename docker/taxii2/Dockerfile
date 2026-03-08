# Last modified: 2026-03-08T11:02:27.873935+00:00

FROM demisto/yarapy:1.0.0.7451089

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends python3-dev wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apt-get purge -y --auto-remove python3-dev wget git
