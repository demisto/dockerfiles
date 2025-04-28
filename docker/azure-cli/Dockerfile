# Use Debian Slim as base
FROM debian:bullseye-slim

# ensure local python is preferred over distribution python
ENV PATH /usr/local/bin:$PATH

ENV DEBIAN_FRONTEND=noninteractive

# Install system tools and Azure CLI dependencies
RUN apt-get update && apt-get install -y \
    curl \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    software-properties-common

# Add Microsoft GPG key and Azure CLI repository
RUN curl -sL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor | tee /etc/apt/trusted.gpg.d/microsoft.gpg > /dev/null \
 && echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ bullseye main" > /etc/apt/sources.list.d/azure-cli.list

# Install Azure CLI
RUN apt-get update && apt-get install -y azure-cli

# Install Python build tools and Rust
RUN apt-get update && apt-get install -y \
    python3-pip \
    python3-dev \
    build-essential \
    git \
    wget \
    rustc \
    cargo \
    libffi-dev \
    libssl-dev

# Upgrade pip
RUN pip3 install --no-cache-dir --upgrade pip

# Copy requirements.txt into the image
COPY requirements.txt /tmp/requirements.txt
# COPY verify.py /verify.py

# Install Python dependencies
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# Cleanup build dependencies and temporary files
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /root/.cargo /tmp/*

CMD ["python3"]