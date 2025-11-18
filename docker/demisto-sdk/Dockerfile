# Last modified: 2025-11-09T00:28:21.973748+00:00
FROM demisto/python3-deb:3.12.12.5735221

WORKDIR /content

ADD https://raw.githubusercontent.com/demisto/demisto-sdk/master/package.json /content/
ADD https://raw.githubusercontent.com/demisto/demisto-sdk/master/package-lock.json /content/

ADD requirements.txt .

# Update package list and upgrade existing packages
RUN apt-get update && apt-get -y --no-install-recommends upgrade

# Install basic development tools
RUN apt-get install -y --no-install-recommends \
    git \
    gcc \
    make \
    build-essential

# Install certificates and networking tools
RUN apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# Install Python development dependencies
RUN apt-get install -y --no-install-recommends \
    libssl-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    libffi-dev \
    python3-dev \
    liblzma-dev

# Install additional development tools and libraries
RUN apt-get install -y --no-install-recommends \
    wget \
    llvm \
    libncurses5-dev \
    libncursesw5-dev \
    xz-utils \
    tk-dev \
    zsh

# Install scientific computing dependencies
RUN apt-get install -y --no-install-recommends \
    gfortran \
    g++ \
    pkg-config \
    libhdf5-dev

# Install Node.js
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash -

RUN apt-get update && apt-get install -y nodejs

# Install Docker CLI
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

RUN echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

RUN apt-get update && apt-get install -y docker-ce-cli containerd
RUN apt-get update && apt-get install -y containerd
# Install Python dependencies
RUN python3 -m pip install --no-cache-dir -r requirements.txt

# Update npm to latest version
RUN npm install -g npm@latest

# Install npm dependencies
RUN npm ci

# Install specific npm packages
RUN npm install -g jsdoc-to-markdown@9.1.3

# List and update npm packages
RUN npm list

RUN npm update

# Verify demisto-sdk installation
RUN demisto-sdk --version

# Default demisto-sdk help
CMD ["demisto-sdk", "--help"]
