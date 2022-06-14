
FROM pypy:3.9-slim-buster

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  libffi-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  libffi-dev \
&& rm -rf /var/lib/apt/lists/*
