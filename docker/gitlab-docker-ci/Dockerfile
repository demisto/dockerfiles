FROM devdemisto/gitlab-content-ci:1.0.0.2492694

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    liblzma-dev \
    libbz2-dev \
    libssl-dev \
    libreadline-dev \
    libsqlite3-dev \
 && rm -rf /var/lib/apt/lists/*

# Set environment variables for pyenv
ENV PYENV_ROOT /root/.pyenv
ENV PATH $PYENV_ROOT/bin:$PATH

# Install Pyenv and other init steps
RUN curl -s https://pyenv.run | bash \
 && eval "$(pyenv init --path)" \
 && eval "$(pyenv init -)" \
 && eval "$(pyenv virtualenv-init -)"

# Setup pyenv
RUN pyenv install -s 2.7.18 && pyenv versions | grep 2.7.18 && \
 pyenv install -s 3.8.15 && pyenv versions | grep 3.8.15 && \
 pyenv install -s 3.9.16 && pyenv versions | grep 3.9.16 && \
 pyenv install -s 3.10.13 && pyenv versions | grep 3.10.13 && \
 pyenv install -s 3.11.0 && pyenv versions | grep 3.11.0 && \
 pyenv install -s 3.12.0 && pyenv versions | grep 3.12.0

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt