FROM python:3.10.6-bullseye

ADD https://raw.githubusercontent.com/demisto/content/master/package.json /content/
ADD https://raw.githubusercontent.com/demisto/content/master/package-lock.json /content/

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
    libffi-dev python3-dev gfortran g++ pkg-config libhdf5-dev \
    -y \
    # install docker
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update && apt-get install docker-ce-cli -y \
    # install demisto-sdk and npm dependency
    && pip install pipx --no-cache-dir \
    && pipx ensurepath \
    && . ~/.bashrc \
    && pipx install demisto-sdk --force \
    && npm install -g jsdoc-to-markdown@5.0.3 \
    && cd content \
    && npm install -g

# Default demisto-sdk help
CMD ["demisto-sdk", "--help"]