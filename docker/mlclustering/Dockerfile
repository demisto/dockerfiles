FROM demisto/python3-deb:3.9.4.18682
COPY requirements.txt .
RUN apt-get update \
&& apt-get install -y --no-install-recommends \
  gcc  g++ cmake\
  python3-dev gfortran wget make git pkg-config libhdf5-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& pip install cmake \
&& git clone https://github.com/DmitryUlyanov/Multicore-TSNE.git \
&& cd Multicore-TSNE \
&& pip install . \
&& python setup.py install \
&& apt-get purge -y --auto-remove \
  python3-dev gfortran wget git gcc  g++  pkg-config libhdf5-dev