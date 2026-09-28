# Last modified: 2026-09-14T20:43:49.071266+00:00

FROM demisto/python3-deb:3.12.14.13053055

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends python3-dev wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  wget \
  git \
&& rm -rf /var/lib/apt/lists/*