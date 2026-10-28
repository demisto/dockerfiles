# Last modified: 2026-10-28T06:16:02.383844+00:00

FROM demisto/opencv:1.0.0.14109060

COPY Pipfile.lock .
COPY Pipfile .

RUN apt-get update && apt-get -t trixie-backports install -y --no-install-recommends \
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
