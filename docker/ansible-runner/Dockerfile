
FROM demisto/python3-deb:3.8.6.13363

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
  linux-libc-dev \
  libc6-dev \
  sshpass \
  openssh-client \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  linux-libc-dev \
  libc6-dev \
  sshpass \
  openssh-client \
&& rm -rf /var/lib/apt/lists/*
