# Last modified: 2026-04-23T11:18:37.611994+00:00
FROM demisto/python3-deb:3.12.13.8411476

COPY requirements.txt .

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
  gcc \
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove gcc \
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev
