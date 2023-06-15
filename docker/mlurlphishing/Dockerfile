FROM demisto/python3-deb:3.10.12.63330

RUN mkdir /model
COPY ./model_docker.pkl /model/model_docker.pkl
RUN chmod -R 775 /model
COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
gcc \
python-dev \
&& apt install libjpeg-dev wget libglib2.0-0 libsm6 libxext6 libgl1-mesa-glx libxrender1 libxrender-dev -y \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python-dev \
  libxrender-dev \
&& rm -rf /var/lib/apt/lists/*


