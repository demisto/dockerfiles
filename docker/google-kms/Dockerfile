FROM demisto/python3-deb:3.12.11.5107264

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
# Last modified: 2025-09-26T16:37:48.012775+00:00
&& rm -rf /var/lib/apt/lists/*
