FROM circleci/node:9.11

RUN sudo apt-get install -y python-dev libxml2-dev libxslt1-dev zlib1g-dev python-setuptools jq

RUN curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash \
  && echo 'export PATH="/home/circleci/.pyenv/bin:$PATH"' >> ~/.bashrc \
  && echo 'eval "$(pyenv init -)"' >> ~/.bashrc \
  && echo 'eval "$(pyenv virtualenv-init -)"' >> ~/.bashrc

COPY requirements.txt .

RUN pip install --user --no-cache-dir -r requirements.txt

RUN sudo easy_install pip
RUN sudo npm install npm -g
RUN sudo npm install -g jsdoc-to-markdown
RUN sudo pip install git+https://github.com/demisto/demisto-py.git@test-content
RUN sudo pip install git+https://github.com/rahulrrixe/parinx.git@master
