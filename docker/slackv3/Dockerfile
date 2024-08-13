
FROM demisto/python3:3.11.9.107902

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends python3-dev build-base libffi-dev wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  lbuild-base \
  libffi-dev \
  wget \
  git \ 
  && rm -rf /var/lib/apt/lists/*