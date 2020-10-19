FROM cimg/base:2020.01

# Global interperters
ENV PYTHON3_VERSION=3.8.5 \
    PYTHON2_VERSION=2.7.18 \
    NODE_VERSION=14.4.0

# Install base packages
RUN sudo apt-get update
RUN sudo apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        git \
        libbz2-dev \
        libffi-dev \
        libncurses5-dev \
        libncursesw5-dev \
        libreadline-dev \
        libsqlite3-dev \
        libssl1.0-dev \
        liblzma-dev \
        # libssl-dev \
        llvm \
        make \
        netbase \
        pkg-config \
        tk-dev \
        wget \
        xz-utils \
        zlib1g-dev

# Install Pyenv (https://github.com/pyenv/pyenv)
ENV LANG="C.UTF-8" \
    LC_ALL="C.UTF-8" \
    PATH="/opt/pyenv/shims:/opt/pyenv/bin:$PATH" \
    PYENV_ROOT="/opt/pyenv" \
    PYENV_SHELL="bash"
RUN sudo rm -rf /var/lib/apt/lists/* /tmp/*
RUN sudo git clone --single-branch --depth 1 https://github.com/pyenv/pyenv.git $PYENV_ROOT
RUN sudo chmod a+wrx $PYENV_ROOT
RUN pyenv install $PYTHON2_VERSION
RUN pyenv install $PYTHON3_VERSION
RUN pyenv global $PYTHON3_VERSION $PYTHON2_VERSION
RUN pip3 install virtualenv

# n install - Node.js manager (https://github.com/tj/n)
ENV N_PREFIX=/opt/n \
    PATH=$N_PREFIX/bin:$PATH
RUN sudo git clone --single-branch --depth 1 https://github.com/tj/n.git $N_PREFIX
RUN cd $N_PREFIX && sudo make install
RUN sudo n $NODE_VERSION

# install gcloud see: https://cloud.google.com/sdk/docs/downloads-apt-get
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
RUN curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
RUN sudo apt-get update
RUN sudo apt-get install -y google-cloud-sdk
