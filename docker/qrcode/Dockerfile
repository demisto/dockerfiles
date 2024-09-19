
FROM demisto/opencv:1.0.0.112276
COPY Pipfile.lock .
COPY Pipfile .
RUN apt-get update && apt-get -t bullseye-backports install -y --no-install-recommends \
  gcc \
  python3-dev \
  libzbar0 \
  build-essential \
  pipenv \
&& pipenv install --system \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  pipenv \
  build-essential \
&& rm -rf /var/lib/apt/lists/*
