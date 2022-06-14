
FROM condaforge/miniforge-pypy3

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  miniforge-pypy3 \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  miniforge-pypy3 \
&& rm -rf /var/lib/apt/lists/*
