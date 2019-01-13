
FROM demisto/python3-deb:1.0.0.53

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python-dev \
  tshark \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python-dev \
&& rm -rf /var/lib/apt/lists/*
