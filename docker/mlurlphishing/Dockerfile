# Last modified: 2026-05-19T04:43:40.954754+00:00

FROM demisto/python3-deb:3.12.13.8927230

RUN mkdir /model
COPY ./model_docker.pkl /model/model_docker.pkl
RUN chmod -R 775 /model
COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
gcc \
python3-dev \
dpkg=1.21.23 \
libcap2=1:2.66-4+deb12u3 \
&& apt install libjpeg-dev wget libglib2.0-0 libsm6 libxext6 libgl1-mesa-glx libxrender1 libxrender-dev -y \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  libxrender-dev \
&& rm -rf /var/lib/apt/lists/*
