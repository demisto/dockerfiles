# Last modified: 2026-11-24T06:05:15.131282+00:00

FROM demisto/python3-deb:3.12.16.15076852

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  yara \
  && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*

