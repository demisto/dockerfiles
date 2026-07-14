# Last modified: 2026-07-14T07:50:42.385524+00:00

FROM demisto/python3-deb:3.12.13.10786156

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

