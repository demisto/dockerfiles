FROM demisto/python3-deb:3.10.1.26968

USER root

RUN apt-get update && apt-get install \
    git \ 
    gcc \
    nodejs \
    npm \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    python2 \
    -y


# Docker cli tools installation
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update && apt-get install docker-ce-cli -y 

# Install node modules for readme validation in demisto-sdk validate
WORKDIR /content
COPY package*.json ./
RUN npm ci

# Install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Work in content folder
WORKDIR /content

# Cleanup
RUN apt-get autoremove -y \
    && apt-get purge gcc -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Default demisto-sdk help
CMD ["demisto-sdk", "--help"]