
FROM demisto/opencv:1.0.0.85821
COPY Pipfile.lock .
COPY Pipfile .
RUN apt-get update && apt-get install -y --no-install-recommends \
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

