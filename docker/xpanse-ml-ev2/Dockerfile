FROM demisto/python3-deb:3.12.12.6878467

COPY requirements.txt .

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
  gcc \
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove gcc \
# Last modified: 2026-01-27T12:16:31.703049+00:00
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev
