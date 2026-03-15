# Last modified: 2026-02-11T15:18:34.933506+00:00

FROM demisto/python3-deb:3.12.12.7090913

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  tshark \
&& rm -rf /var/lib/apt/lists/*
