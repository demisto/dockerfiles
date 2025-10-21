FROM demisto/python3-deb:3.12.11.5107264

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*

# Installs p7zip-full for general archive extraction.
RUN apt-get update && apt-get install -y --no-install-recommends p7zip-full \
  && rm -rf /var/lib/apt/lists/*

# Add a new sources list file that includes the contrib and non-free repositories
RUN echo "deb http://deb.debian.org/debian bookworm contrib non-free" >> /etc/apt/sources.list.d/contrib-nonfree.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends unrar \
    && rm -rf /var/lib/apt/lists/*
