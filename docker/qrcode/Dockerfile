
FROM demisto/python3-deb:3.10.13.85666
COPY Pipfile.lock .
COPY Pipfile .
RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
  libzbar0 \
  build-essential \
  zbar-tools \
  libzbar-dev \
  pipenv \
&& pipenv install --system \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  pipenv \
  build-essential \
&& rm -rf /var/lib/apt/lists/*

