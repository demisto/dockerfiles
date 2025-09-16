
FROM demisto/python3-deb:3.12.11.4801753

# https://github.com/mwilliamson/jq.py?tab=readme-ov-file#debian-ubuntu-or-relatives
RUN apt-get update && apt-get install automake build-essential libtool python-dev -y

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*
