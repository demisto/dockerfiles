
FROM demisto/python3-deb:3.10.10.49238

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends gcc libgl1-mesa-glx \
  && pip install --no-cache-dir -r requirements.txt
