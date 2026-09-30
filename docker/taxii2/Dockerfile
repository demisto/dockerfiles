# Last modified: 2026-09-30T05:03:25.887021+00:00

FROM demisto/yarapy:1.0.0.13398989

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends python3-dev wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apt-get purge -y --auto-remove python3-dev wget git
