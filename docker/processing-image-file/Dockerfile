
FROM demisto/python3-deb:3.10.10.49238

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends gcc libglib2.0-0 libsm6 libxrender1 libxext6 \
  && pip install --no-cache-dir -r requirements.txt
