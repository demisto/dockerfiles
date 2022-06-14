
FROM condaforge/miniforge-pypy3

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  libffi-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  libffi-dev \
&& rm -rf /var/lib/apt/lists/*
