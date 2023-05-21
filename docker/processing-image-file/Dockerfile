
FROM demisto/python3-deb:3.10.11.59575

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends gcc python-dev libjpeg-dev wget libglib2.0-0 libsm6 libxext6 libgl1-mesa-glx libxrender1 libxrender-dev \
  && pip install --no-cache-dir -r requirements.txt
