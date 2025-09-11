
FROM demisto/python3-deb:3.12.11.4801753

RUN apt-get update && apt-get install build-essential flex bison libtool make automake autoconf -y

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
  autoconf \
  automake \
  libtool \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  autoconf \
  automake \
  libtool \
&& rm -rf /var/lib/apt/lists/*