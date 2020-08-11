
FROM demisto/python3-deb:3.8.5.10453

COPY requirements.txt .

RUN apt-get update && apt-get -t buster-backports install -y --no-install-recommends \
  yara \
  && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python-dev \
&& rm -rf /var/lib/apt/lists/*

