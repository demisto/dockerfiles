FROM circleci/python:3.7.3-stretch-node

RUN sudo apt-get update && \
  sudo apt-get install -y --no-install-recommends python-dev libxml2-dev libxslt1-dev zlib1g-dev python-setuptools jq \
  make build-essential libssl-dev libbz2-dev \
  libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
  xz-utils tk-dev libffi-dev liblzma-dev python-openssl \
  python3 python3-dev

RUN curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash \
  && echo 'export PATH="/home/circleci/.pyenv/bin:$PATH"' >> ~/.bashrc \
  && echo 'eval "$(pyenv init -)"' >> ~/.bashrc \
  && echo 'eval "$(pyenv virtualenv-init -)"' >> ~/.bashrc

# install python versions
RUN bash -i -c 'pyenv install 2.7.15 && pyenv versions | grep 2.7.15'
# python 3.7.2 requires newer openssl than provided with debian 8
RUN bash -i -c 'pyenv install 3.7.3 && pyenv versions | grep 3.7.3'
RUN bash -i -c 'pyenv global 2.7.15 3.7.3'
RUN bash -i -c 'pyenv exec pip install --upgrade --no-cache-dir pip'
RUN bash -i -c 'pyenv exec pip3 install --upgrade --no-cache-dir pip'
RUN bash -i -c 'pyenv exec pip install --no-cache-dir git+https://github.com/demisto/demisto-py.git@test-content'
RUN bash -i -c 'pyenv exec pip install --no-cache-dir git+https://github.com/rahulrrixe/parinx.git@master'

COPY requirements.txt .

RUN bash -i -c 'pyenv exec pip install --no-cache-dir -r requirements.txt'

RUN sudo npm install npm -g
RUN sudo npm install -g jsdoc-to-markdown
