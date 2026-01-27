# Last modified: 2026-01-27T12:16:31.703049+00:00

FROM demisto/python3-deb:3.12.12.6878467

RUN mkdir /model
COPY ./model_docker.pkl /model/model_docker.pkl
RUN chmod -R 775 /model
COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
gcc \
python3-dev \
&& apt install libjpeg-dev wget libglib2.0-0 libsm6 libxext6 libgl1-mesa-glx libxrender1 libxrender-dev -y \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  libxrender-dev \
&& rm -rf /var/lib/apt/lists/*

