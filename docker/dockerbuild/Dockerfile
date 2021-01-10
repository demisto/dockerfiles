FROM circleci/python:2.7.17-stretch

# Setup pyenv and install extra python versions
RUN curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash \
  && echo 'export PATH="/home/circleci/.pyenv/bin:$PATH"' >> ~/.bashrc \
  && echo 'eval "$(pyenv init -)"' >> ~/.bashrc \
  && echo 'eval "$(pyenv virtualenv-init -)"' >> ~/.bashrc

RUN bash -i -c 'pyenv install 3.7.6 && pyenv versions | grep 3.7.6'
RUN bash -i -c 'pyenv install 3.8.1 && pyenv versions | grep 3.8.1'
RUN bash -i -c 'pyenv install 3.6.10 && pyenv versions | grep 3.6.10'
RUN bash -i -c 'pyenv install 3.9.0 && pyenv versions | grep 3.9.0'

COPY requirements.txt .

RUN pip install --user --no-cache-dir -r requirements.txt
RUN bash -i -c 'pyenv shell 3.7.6 && pyenv exec pip3 install --no-cache-dir -r requirements.txt'
