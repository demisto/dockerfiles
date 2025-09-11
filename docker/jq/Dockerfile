
FROM demisto/python3-deb:3.12.11.4801753

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
  build-essential \
  flex \
  bison \
  libtool \
  make \
  automake \
  autoconf \
  gettext \
  pkg-config \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  build-essential \
  flex \
  bison \
  libtool \
  make \
  automake \
  autoconf \
  gettext \
  pkg-config \
&& rm -rf /var/lib/apt/lists/*
