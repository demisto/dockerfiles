FROM circleci/python:3.10.1

# Setup pyenv and install extra python versions
RUN curl -L https://github.com/pyenv/pyenv-installer/raw/master/bin/pyenv-installer | bash \
  && echo 'export PATH="/home/circleci/.pyenv/bin:$PATH"' >> ~/.bashrc \
  && echo 'eval "$(pyenv init -)"' >> ~/.bashrc \
  && echo 'eval "$(pyenv virtualenv-init -)"' >> ~/.bashrc

RUN bash -i -c 'pyenv install 2.7.18 && pyenv versions | grep 2.7.18'
RUN bash -i -c 'pyenv install 3.7.6 && pyenv versions | grep 3.7.6'
RUN bash -i -c 'pyenv install 3.8.1 && pyenv versions | grep 3.8.1'
RUN bash -i -c 'pyenv install 3.6.10 && pyenv versions | grep 3.6.10'
RUN bash -i -c 'pyenv install 3.9.0 && pyenv versions | grep 3.9.0'
RUN bash -i -c 'pyenv install 3.10.0 && pyenv versions | grep 3.10.0'

RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" |  tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - \
    && apt-get update && apt-get install -y docker-ce-cli kubectl



COPY requirements.txt .

RUN pip install --user --no-cache-dir -r requirements.txt
RUN bash -i -c 'pyenv shell 3.7.6 && pyenv exec pip3 install --no-cache-dir -r requirements.txt'
