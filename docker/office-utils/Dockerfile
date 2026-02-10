# Last modified: 2026-02-10T11:38:56.944817+00:00

FROM demisto/python3-deb:3.12.12.7081038

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/share/man/man1 \
&& apt-get update && apt-get install -y --no-install-recommends \
  libgpgme11 \
  libreoffice \
  default-jre-headless \
&& rm -rf /var/lib/apt/lists/*
