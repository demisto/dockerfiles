# Last modified: 2023-01-04T00:13:10.301105+00:00
FROM circleci/python:3.10.1

# Setup pyenv + poetry and install extra python versions
RUN curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash \
  && curl -sSL https://install.python-poetry.org | python3 \
  && poetry --version \
  && poetry self add poetry-plugin-export \
  && echo 'export PATH="/home/circleci/.pyenv/bin:$PATH"' >> ~/.bashrc \
  && echo 'eval "$(pyenv init -)"' >> ~/.bashrc \
  && echo 'eval "$(pyenv virtualenv-init -)"' >> ~/.bashrc

RUN bash -i -c 'pyenv install 2.7.18 && pyenv versions | grep 2.7.18'
RUN bash -i -c 'pyenv install 3.7.6 && pyenv versions | grep 3.7.6'
RUN bash -i -c 'pyenv install 3.8.1 && pyenv versions | grep 3.8.1'
RUN bash -i -c 'pyenv install 3.6.10 && pyenv versions | grep 3.6.10'
RUN bash -i -c 'pyenv install 3.9.0 && pyenv versions | grep 3.9.0'
RUN bash -i -c 'pyenv install 3.10.0 && pyenv versions | grep 3.10.0'

COPY requirements.txt .

RUN pip install --user --no-cache-dir -r requirements.txt
RUN bash -i -c 'pyenv shell 3.7.6 && pyenv exec pip3 install --no-cache-dir -r requirements.txt'
