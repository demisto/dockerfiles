
FROM demisto/python3-deb:3.10.11.59575

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
  linux-libc-dev \
  libc6-dev \
  sshpass \
  openssh-client \
&& pip install --no-cache-dir -r requirements.txt \
&& pip install https://github.com/vmware/vsphere-automation-sdk-python/archive/refs/tags/v7.0.3.2.tar.gz \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  linux-libc-dev \
  libc6-dev \
&& rm -rf /var/lib/apt/lists/*
