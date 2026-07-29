# Last modified: 2026-07-20T17:02:14.442238+00:00

FROM demisto/python3-deb:3.12.13.11039180

COPY requirements.txt .

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
  gcc \
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove gcc \
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev
