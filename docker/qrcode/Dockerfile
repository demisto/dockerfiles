# Last modified: 2025-12-22T11:51:17.307255+00:00

FROM demisto/opencv:1.0.0.6361953

COPY Pipfile.lock .
COPY Pipfile .

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
