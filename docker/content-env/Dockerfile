FROM demisto/python3-deb:3.10.4.30603

ENV PATH /root/.local/bin:$PATH
ENV PYTHON_VERSION 3.10.4

# Python requirements
ADD requirements.txt .

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
    python2 \
    libffi-dev \
    libssl-dev \
    software-properties-common \
    apt-transport-https \
    gpgv \
    bzip2 \
    ncurses \
    lib32readline7 \
    sqlite3 \
    lzma \
    -y \
    # Docker cli, gsutil, gcloud, powershell, poetry tools installation
    && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" |  tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - \
    && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | apt-key add - \
    && curl -sSL https://install.python-poetry.org | python3 - \
    && sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-bullseye-prod bullseye main" > /etc/apt/sources.list.d/microsoft.list' \
    && add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable" \
    && apt-get update && apt-get install google-cloud-sdk docker-ce-cli kubectl powershell -y \
    && python --version \
    && gcloud --version \
    && gsutil --version \
    && docker --version \
    && poetry --version \
    # install content dependencies
    && python -m pip install --no-cache-dir -r requirements.txt \
    && git clone --depth 1 https://github.com/demisto/content.git \
    && cd content \
    && demisto-sdk --version \
    && poetry install \
    && export POETRY_VENV_PATH=$(poetry env info --path) \
    && echo $POETRY_VENV_PATH \
    && npm install -g \
    && rm -rf /content \
    # install zsh and oh-my-zsh with plugins 
    && cd ~ \
    && sh -c "$(wget -O- https://github.com/deluan/zsh-in-docker/releases/download/v1.1.2/zsh-in-docker.sh)" -- \
    -p https://github.com/zsh-users/zsh-autosuggestions \
    -p https://github.com/zsh-users/zsh-completions \
    -p https://github.com/zsh-users/zsh-syntax-highlighting \
    -p git \
    -p poetry

RUN poetry completions zsh > $HOME/.oh-my-zsh/custom/plugins/poetry \
    && curl -fSSL https://pyenv.run | bash \
    && echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc \
    && echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc \
    && echo 'eval "$(pyenv init -)"' >> ~/.zshrc \
    && source ~/.zshrc \
    && pyenv update \
    && pyenv install $PYTHON_VERSION \
    && pyenv global $PYTHON_VERSION \
    # check if demisto-sdk is still available
    && demisto-sdk --version


ENV POETRY_VENV_PATH $POETRY_VENV_PATH

# Default demisto-sdk help
CMD ["demisto-sdk", "--help"]