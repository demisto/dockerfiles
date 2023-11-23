# Last modified: 2023-11-23T00:13:10.301105+00:00
FROM python:3.10.13-slim-bookworm

COPY localtime /etc/localtime
RUN set -ex; apt-get update; apt-get install -y --no-install-recommends autoconf automake bzip2 dpkg-dev file g++ gcc  \
    imagemagick libbz2-dev libc6-dev libcurl4-openssl-dev libdb-dev libevent-dev libffi-dev libgdbm-dev libglib2.0-dev \
    libgmp-dev libjpeg-dev libkrb5-dev liblzma-dev libmagickcore-dev libmagickwand-dev libmaxminddb-dev libncurses5-dev  \
    libncursesw5-dev libpng-dev libpq-dev libreadline-dev libsqlite3-dev libssl-dev libtool libwebp-dev libxml2-dev  \
    libxslt-dev libyaml-dev make patch unzip xz-utils zlib1g-dev \
    $( if apt-cache show 'default-libmysqlclient-dev' 2>/dev/null | grep -q '^Version:';  \
    then echo 'default-libmysqlclient-dev'; else echo 'libmysqlclient-dev'; fi )
RUN  apt-get install -y git mercurial xvfb apt locales sudo openssh-client ca-certificates tar gzip  \
    parallel net-tools unzip zip bzip2 gnupg curl wget build-essential jq docker docker-compose libgbm1
# Setup pyenv + poetry and install extra python versions
RUN curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash \
  && echo 'export PYENV_ROOT="$HOME/.pyenv" && export PATH="$HOME/.pyenv/bin:$PATH"' >> ~/.bashrc \
  && echo 'eval "$(pyenv init -)"' >> ~/.bashrc \
  && echo 'eval "$(pyenv virtualenv-init -)"' >> ~/.bashrc

RUN bash -i -c 'pyenv install 2.7.18 && pyenv versions | grep 2.7.18'
RUN bash -i -c 'pyenv install 3.9.0 && pyenv versions | grep 3.9.0'
RUN bash -i -c 'pyenv install 3.10.0 && pyenv versions | grep 3.10.0'
RUN bash -i -c 'pyenv install 3.11.0 && pyenv versions | grep 3.11.0'
RUN bash -i -c 'pyenv install 3.12.0 && pyenv versions | grep 3.12.0'

COPY requirements.txt .

RUN pip install --user --no-cache-dir -r requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt \
    && poetry --version && pipenv --version
RUN rm -rf /var/lib/apt/lists/*
