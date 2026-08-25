# Last modified: 2026-08-25T00:56:46.048495+00:00

FROM demisto/python3-deb:3.12.13.12042988

COPY requirements.txt .

# in order to install the "azure-keyvault" module we need pip==24.0, so install it and after that upgrade again
RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
  linux-libc-dev \
  libc6-dev \
  sshpass \
  openssh-client \
&& pip install pip==24.0 \
&& pip install --no-cache-dir -r requirements.txt \
&& pip install --upgrade pip \
&& pip install https://github.com/vmware/vsphere-automation-sdk-python/archive/refs/tags/v7.0.3.2.tar.gz \
&& pip install --upgrade azure-storage-blob \
&& pip install --no-cache-dir cryptography>=50.0.0 \
&& pip uninstall aiohttp -y \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  linux-libc-dev \
  libc6-dev \
&& rm -rf /var/lib/apt/lists/*
