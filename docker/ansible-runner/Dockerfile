
FROM demisto/python3-deb:3.10.9.42461

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
  linux-libc-dev \
  libc6-dev \
  git \
  sshpass \
  openssh-client \
&& pip install --no-cache-dir -r requirements.txt \
&& pip install git+https://github.com/vmware/vsphere-automation-sdk-python.git@v7.0.1.0 \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  git \
  linux-libc-dev \
  libc6-dev \
&& rm -rf /var/lib/apt/lists/*
