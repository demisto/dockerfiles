
FROM demisto/python3-deb:3.10.12.62632

COPY requirements.txt .
# see: https://github.com/rakyll/hey
ADD https://hey-release.s3.us-east-2.amazonaws.com/hey_linux_amd64 /usr/bin/hey
RUN chmod +x /usr/bin/hey
RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*
