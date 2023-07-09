
FROM demisto/python-deb:2.7.18.64530

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python2-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python2-dev \
&& rm -rf /var/lib/apt/lists/*
