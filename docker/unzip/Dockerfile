FROM demisto/python3-deb:3.12.13.7529797

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*

# Installs 7zip from backports (>= 23.00) for general archive extraction.
RUN echo "deb http://deb.debian.org/debian bookworm-backports main" >> /etc/apt/sources.list.d/backports.list \
  && apt-get update \
  && apt-get install -y --no-install-recommends -t bookworm-backports 7zip \
  && rm -rf /var/lib/apt/lists/*

# Add a new sources list file that includes the contrib and non-free repositories
RUN echo "deb http://deb.debian.org/debian bookworm contrib non-free" >> /etc/apt/sources.list.d/contrib-nonfree.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends unrar \
# Last modified: 2026-03-16T13:17:22.655100+00:00
    && rm -rf /var/lib/apt/lists/*
