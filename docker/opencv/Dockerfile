
FROM demisto/python3-deb:3.12.11.4027491

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& apt install wget libglib2.0-0 libsm6 \
libxext6 libgl1-mesa-glx libxrender1 libxrender-dev -y \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  libxrender-dev \
&& rm -rf /var/lib/apt/lists/*

