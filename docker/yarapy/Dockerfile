# Last modified: 2026-08-26T16:55:27.358267+00:00

FROM demisto/python3-deb:3.12.14.12343672

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

