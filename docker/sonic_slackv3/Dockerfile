
FROM condaforge/miniforge-pypy3

COPY requirements.txt .

RUN apt-get update \
&& pip install --no-cache-dir -r requirements.txt \
&& rm -rf /var/lib/apt/lists/*
