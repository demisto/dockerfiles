# Last modified: 2025-12-14T12:44:32.829031+00:00

FROM demisto/python3-deb:3.12.12.6269782

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
&& pip uninstall aiohttp -y \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  linux-libc-dev \
  libc6-dev \
&& rm -rf /var/lib/apt/lists/*
