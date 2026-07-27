# Last modified: 2026-07-27T09:20:28.296998+00:00

FROM demisto/opencv:1.0.0.11195141

COPY Pipfile.lock .
COPY Pipfile .

# libzbar0: pyzbar runtime dep (build tools removed afterwards).
RUN apt-get update && apt-get -t bookworm-backports install -y --no-install-recommends \
  gcc \
  python3-dev \
  libzbar0 \
  build-essential \
  && pip install --no-cache-dir pipenv \
  && pipenv install --system --deploy \
  && apt-get purge -y --auto-remove \
    gcc \
    python3-dev \
    build-essential \
  && rm -rf /var/lib/apt/lists/* \
  && pip uninstall -y pipenv
