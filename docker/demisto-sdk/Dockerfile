FROM demisto/python3-deb:3.10.1.26968


RUN apt-get update && apt-get install \
    git \ 
    gcc \
    nodejs \
    npm \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    make \
    build-essential \
    libssl-dev zlib1g-dev libbz2-dev \
    libreadline-dev libsqlite3-dev wget llvm libncurses5-dev libncursesw5-dev \
    xz-utils tk-dev libffi-dev liblzma-dev zsh \
    -y 

# Docker cli tools installation
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update && apt-get install docker-ce-cli -y



# Install node modules for readme validation in demisto-sdk validate
ADD https://raw.githubusercontent.com/demisto/demisto-sdk/master/package.json .
ADD https://raw.githubusercontent.com/demisto/demisto-sdk/master/package-lock.json .

# Python requirements
ADD requirements.txt .
RUN npm ci && python3 -m pip install --no-cache-dir -r requirements.txt && rm requirements.txt \
    && poetry config virtualenvs.in-project true

# apt-get Cleanup
RUN apt-get autoremove -y \
    && apt-get purge gcc -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Default demisto-sdk help
CMD ["demisto-sdk", "--help"]