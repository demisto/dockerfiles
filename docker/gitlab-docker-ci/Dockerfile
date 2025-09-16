FROM devdemisto/gitlab-content-ci:1.0.0.2492694

# Clean up any existing backports references that may cause conflicts
RUN sed -i '/bullseye-backports/d' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true \
&& sed -i '/bookworm-backports/d' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true

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
 pyenv install -s 3.12.11 && pyenv versions | grep 3.12.11 && \
 pyenv install -s 3.13.7 && pyenv versions | grep 3.13.7

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt