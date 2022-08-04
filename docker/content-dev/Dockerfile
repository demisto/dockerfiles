FROM python:3.10.5-bullseye

ENV PATH /root/.local/bin:$PATH

# install zsh first
RUN apt-get update && apt-get install -y zsh wget \
    && sh -c "$(wget -O- https://github.com/deluan/zsh-in-docker/releases/download/v1.1.2/zsh-in-docker.sh)" -- \
    -p https://github.com/zsh-users/zsh-autosuggestions \
    -p https://github.com/zsh-users/zsh-completions \
    -p https://github.com/zsh-users/zsh-syntax-highlighting

ADD .p10k.zsh /root/.p10k.zsh
ADD .zshrc /root/.zshrc

SHELL [ "/bin/zsh", "-c" ]

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
    python2-dev \
    python-dev \
    libffi-dev \
    libssl-dev \
    software-properties-common \
    apt-transport-https \
    dpkg-dev \
    gcc \
    libbz2-dev \
    libc6-dev \
    libdb-dev \
    libgdbm-dev \
    libncursesw5-dev \
    libreadline-dev \
    libsqlite3-dev \
    tk-dev \
    xz-utils \
    zlib1g-dev \
    libpq-dev \
    libxml2-dev \
    libxslt1-dev \
    libldap2-dev \ 
    libsasl2-dev \
    -y \
    # Docker cli, gsutil, gcloud, poetry tools installation
    && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" |  tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - \
    && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | apt-key add - \
    && curl -fsSL https://install.python-poetry.org | python3 - \
    && add-apt-repository "deb [arch=$(dpkg --print-architecture)] https://download.docker.com/linux/ubuntu bionic stable" \
    && apt-get update && apt-get install google-cloud-sdk docker-ce-cli -y \
    && curl -fSSL https://pyenv.run | bash \
    && pip install pipx \
    && pipx ensurepath \
    && source ~/.zshrc \
    && pipx install demisto-sdk \
    && demisto-sdk --version \
    && source ~/.zshrc \
    && python --version \
    && gcloud --version \
    && gsutil --version \
    && docker --version \
    && poetry --version \
    && pyenv --version \
    && pyenv update \
    && source ~/.zshrc \
    && npm install -g jsdoc-to-markdown@5.0.3 \
    # install poetry plugin for oh my zsh 
    && poetry completions zsh > $HOME/.oh-my-zsh/custom/plugins/poetry


# Default demisto-sdk help
CMD ["demisto-sdk", "--help"]