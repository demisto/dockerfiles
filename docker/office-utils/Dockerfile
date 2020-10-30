
FROM demisto/python3-deb:3.8.6.12176

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python-dev \
&& rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/share/man/man1 \
&& apt-get update && apt-get install -y --no-install-recommends \
  libgpgme11 \
  libreoffice \
  default-jre-headless \
&& rm -rf /var/lib/apt/lists/*
