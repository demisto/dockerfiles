
FROM demisto/python-deb:2.7.16.2245

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python-dev \
&& rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/share/man/man1 \
&& apt-get update && apt-get install -y --no-install-recommends \
  libgpgmepp6 \
  libreoffice-base \
  libreoffice-calc \
  libreoffice-core \
  libreoffice-draw \
  libreoffice-impress \
  libreoffice-math \
  libreoffice-report-builder-bin \
  libreoffice-writer \
  libreoffice-avmedia-backend-gstreamer \
  python3-uno \
  libreoffice \
  unoconv \
&& rm -rf /var/lib/apt/lists/*
