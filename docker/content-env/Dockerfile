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
    zsh \
    wget \
    python3-dev \
    libffi-dev \
    libssl-dev \
    software-properties-common \
    apt-transport-https \
    gpgv \
    -y 

# Docker cli, gsutil, gcloud, powershell tools installation
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" |  tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - \
    && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | apt-key add - \
    && sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-bullseye-prod bullseye main" > /etc/apt/sources.list.d/microsoft.list' \
    && add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable" \
    && apt-get update && apt-get install google-cloud-sdk docker-ce-cli kubectl powershell -y \
    && gcloud --version \
    && gsutil --version \
    && docker --version

# Python requirements
ADD requirements.txt .

# install poetry reqs
RUN python3 -m pip install --no-cache-dir -r requirements.txt \
    && git clone https://github.com/demisto/content.git \
    && cd content \
    && poetry --version \
    && demisto-sdk --version \
    && poetry install \
    && npm ci \
    && export POETRY_VENV_PATH=$(poetry env info -p)

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

RUN rm 

# Default demisto-sdk help
CMD ["demisto-sdk", "--help"]