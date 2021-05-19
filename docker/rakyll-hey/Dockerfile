
FROM demisto/python3-deb:3.9.5.20070

COPY requirements.txt .
COPY hey_0.1.4_amd64.deb .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& dpkg -i hey_0.1.4_amd64.deb \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*
