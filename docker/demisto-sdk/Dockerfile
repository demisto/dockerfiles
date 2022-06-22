FROM demisto/python3-deb:3.10.4.30603

# All content dependencies preinstalled
RUN apt-get update && apt-get -y --no-install-recommends upgrade && apt-get install \
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
    libffi-dev openssl-dev \
    python3-dev gfortran g++ pkg-config libhdf5-dev \
    -y 

# Docker cli tools installation
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update && apt-get install docker-ce-cli -y

# Install Powershell
RUN curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | apt-key add - \
    && sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-bullseye-prod bullseye main" > /etc/apt/sources.list.d/microsoft.list' \
    && apt-get update && apt-get install -y powershell


# Install node modules for readme validation in demisto-sdk validate
ADD https://raw.githubusercontent.com/demisto/demisto-sdk/master/package.json .
ADD https://raw.githubusercontent.com/demisto/demisto-sdk/master/package-lock.json .

# Python requirements
ADD requirements.txt .
RUN npm ci && python3 -m pip install --no-cache-dir -r requirements.txt && rm requirements.txt

# install zsh and pyenv
RUN cd ~ \
    && sh -c "$(wget -O- https://github.com/deluan/zsh-in-docker/releases/download/v1.1.2/zsh-in-docker.sh)" -- \
    -p https://github.com/zsh-users/zsh-autosuggestions \
    -p https://github.com/zsh-users/zsh-completions \
    -p https://github.com/zsh-users/zsh-syntax-highlighting \
    -p git 

RUN git clone https://github.com/pyenv/pyenv.git ~/.pyenv \
    && echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc \
    && echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc \
    && echo 'eval "$(pyenv init -)"' >> ~/.zshrc

# apt-get Cleanup
RUN apt-get autoremove -y \
    && apt-get purge gcc -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Default demisto-sdk help
CMD ["demisto-sdk", "--help"]