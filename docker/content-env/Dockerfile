FROM demisto/python3-deb:3.10.4.30603

ENV PATH /root/.pyenv/bin:/root/.local/bin:$PATH
ENV PYENV_ROOT /root/.pyenv

ARG PYTHON_VERSION 3.10.4
# Python requirements
ADD requirements.txt .

# install zsh first
RUN apt-get update && apt-get install -y zsh wget \
    && sh -c "$(wget -O- https://github.com/deluan/zsh-in-docker/releases/download/v1.1.2/zsh-in-docker.sh)" -- \
    -p https://github.com/zsh-users/zsh-autosuggestions \
    -p https://github.com/zsh-users/zsh-completions \
    -p https://github.com/zsh-users/zsh-syntax-highlighting \
    -p git \
    -p poetry

SHELL [ "/bin/zsh", "-c" ]
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
    python3-dev \
    python2 \
    libffi-dev \
    libssl-dev \
    software-properties-common \
    apt-transport-https \
    gpgv \
    bzip2 \
    ncurses-dev \
    lib32readline-dev \
    sqlite3 \
    lzma \
    -y \
    && python -m pip install --no-cache-dir -r requirements.txt \
    # Docker cli, gsutil, gcloud, powershell, poetry tools installation
    && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" |  tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - \
    && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | apt-key add - \
    && curl -sSL https://install.python-poetry.org | python3 - \
    && sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-bullseye-prod bullseye main" > /etc/apt/sources.list.d/microsoft.list' \
    && add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable" \
    && apt-get update && apt-get install google-cloud-sdk docker-ce-cli kubectl powershell -y \
    && curl -fSSL https://pyenv.run | bash \
    && echo 'eval "$(pyenv init -)"' >> ~/.zshrc \
    && source ~/.zshrc \
    && python --version \
    && gcloud --version \
    && gsutil --version \
    && docker --version \
    && poetry --version \
    && pyenv --version \
    && pyenv update \
    && pyenv install $PYTHON_VERSION \
    && pyenv global $PYTHON_VERSION \
    # install content dependencies
    && python -m pip install --no-cache-dir -r requirements.txt \
    && git clone --depth 1 https://github.com/demisto/content.git \
    && cd content \
    && demisto-sdk --version \
    && poetry install \
    && POETRY_VENV_PATH=$(poetry run python -c 'import sys; print(sys.executable)') \
    && echo "export POETRY_VENV_PATH=$POETRY_VENV_PATH" >> ~/.zshrc \
    && npm install -g \
    && rm -rf /content \
    # install zsh and oh-my-zsh with plugins 
    && poetry completions zsh > $HOME/.oh-my-zsh/custom/plugins/poetry 


# Default demisto-sdk help
CMD ["demisto-sdk", "--help"]