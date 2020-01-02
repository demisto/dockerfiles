
FROM demisto/python-deb:2.7.17.4583

COPY requirements.txt .

RUN apt-get update && apt-get install -y zlib1g-dev libicu-dev g++

RUN pip install --upgrade pip

RUN apt-get update && apt-get install -y gcc g++

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python-dev \
&& rm -rf /var/lib/apt/lists/*
