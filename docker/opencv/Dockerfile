# Last modified: 2026-01-20T16:48:56.856474+00:00

FROM demisto/python3-deb:3.12.12.6795448

COPY requirements.txt .

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
  wget \
  libglib2.0-0 \
  libsm6 \
  libxext6 \
  libgl1-mesa-glx \
  libxrender1 \
  libxrender-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  libxrender-dev \
&& rm -rf /var/lib/apt/lists/*

