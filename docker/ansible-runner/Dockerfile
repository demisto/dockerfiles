
FROM demisto/python3-deb:3.11.9.104509

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
&& pip uninstall azure-storage-blob -y \
&& pip install azure-storage-blob \
&& pip install -r /usr/local/lib/python3.11/site-packages/ansible_collections/azure/azcollection/requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  linux-libc-dev \
  libc6-dev \
&& rm -rf /var/lib/apt/lists/*
