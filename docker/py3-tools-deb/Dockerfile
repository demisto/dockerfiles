# This is a py-tools image that is based on debian linux
FROM demisto/python3-deb:3.10.8.36615

COPY requirements.txt .

RUN apt-get update && apt-get install -y build-essential wget git libffi-dev \
  && pip install --no-cache-dir -r requirements.txt \
  && pip uninstall -y pcodedmp
