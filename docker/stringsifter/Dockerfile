FROM demisto/python3-deb:3.8.6.14507

COPY requirements.txt .

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends python3-dev make gcc g++ wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apt-get purge -y --auto-remove gcc g++ make python3-dev
