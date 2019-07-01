FROM circleci/python:3.7.3-stretch

# Setup pyenv and install python 3.7.1
RUN curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash \
  && echo 'export PATH="/home/circleci/.pyenv/bin:$PATH"' >> ~/.bashrc \
  && echo 'eval "$(pyenv init -)"' >> ~/.bashrc \
  && echo 'eval "$(pyenv virtualenv-init -)"' >> ~/.bashrc

RUN bash -i -c 'pyenv install 3.7.1 && pyenv versions | grep 3.7.1'

COPY requirements.txt .

RUN pip install --user --no-cache-dir -r requirements.txt
