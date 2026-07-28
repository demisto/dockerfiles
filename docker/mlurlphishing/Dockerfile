# Last modified: 2026-06-28T04:49:21.857846+00:00

FROM demisto/python3-deb:3.12.13.10448099

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
# ---------------------------------------------------------------------------
# TEMPORARY: image-size padding for testing only. DO NOT MERGE TO PRODUCTION.
# Writes ~1.2GB of incompressible random data as a dedicated final layer so
# the total image size is approximately 2GB. Random data is used (instead of
# fallocate/truncate) because sparse/zero-filled files can be stored compactly
# in the image layer and would not reliably grow the image.
# To revert: delete this entire block (the file lives in its own layer).
# ---------------------------------------------------------------------------
RUN dd if=/dev/urandom of=/padding.bin bs=1M count=1200