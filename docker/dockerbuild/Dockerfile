# Last modified: 2023-11-23T00:13:10.301105+00:00
FROM python:3.10.13-slim-bookworm

COPY localtime /etc/localtime

RUN apt-get update && apt-get install -y git mercurial xvfb apt locales sudo openssh-client ca-certificates tar gzip  \
    parallel net-tools unzip zip bzip2 gnupg curl wget make jq docker docker-compose libgbm1
# Setup pyenv + poetry and install extra python versions
RUN curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash \
  && curl -sSL https://install.python-poetry.org | python3 \
  && export PATH="/root/.local/bin:$PATH
  && poetry --version \
  && poetry self add poetry-plugin-export \
  && echo 'export PATH="/home/circleci/.pyenv/bin:$PATH"' >> ~/.bashrc \
  && echo 'eval "$(pyenv init -)"' >> ~/.bashrc \
  && echo 'eval "$(pyenv virtualenv-init -)"' >> ~/.bashrc

RUN bash -i -c 'pyenv install 2.7.18 && pyenv versions | grep 2.7.18'
RUN bash -i -c 'pyenv install 3.9.0 && pyenv versions | grep 3.9.0'
RUN bash -i -c 'pyenv install 3.10.0 && pyenv versions | grep 3.10.0'
RUN bash -i -c 'pyenv install 3.11.0 && pyenv versions | grep 3.11.0'
RUN bash -i -c 'pyenv install 3.12.0 && pyenv versions | grep 3.12.0'

COPY requirements.txt .

RUN pip install --user --no-cache-dir -r requirements.txt
RUN bash -i -c 'pyenv shell 3.10.0 && pyenv exec pip3 install --no-cache-dir -r requirements.txt'
