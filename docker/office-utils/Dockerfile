# Last modified: 2025-11-05T04:37:37.303729+00:00

FROM demisto/python3-deb:3.12.12.5735221

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
