
FROM demisto/python3-deb:3.9.1.14969

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python-dev \
&& apt install python3 python3-distutils wget libglib2.0-0 libsm6 libxext6 libgl1-mesa-glx libxrender-dev -y \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python-dev \
&& rm -rf /var/lib/apt/lists/*
