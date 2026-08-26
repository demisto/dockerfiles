# Last modified: 2026-08-26T12:53:00.671732+00:00

FROM demisto/python3-deb:3.12.14.12322615

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends python3-dev wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  wget \
  git \
&& rm -rf /var/lib/apt/lists/*