FROM devdemisto/gitlab-content-ci:1.0.0.64455
COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

# Setup pyenv
RUN pyenv install -s 2.7.18 && pyenv versions | grep 2.7.18 && \
 pyenv install -s 3.8.15 && pyenv versions | grep 3.8.15 && \
 pyenv install -s 3.9.16 && pyenv versions | grep 3.9.16 && \
 pyenv install -s 3.10.13 && pyenv versions | grep 3.10.13 && \
 pyenv install -s 3.11.0 && pyenv versions | grep 3.11.0 && \
 pyenv install -s 3.12.0 && pyenv versions | grep 3.12.0 && \
pyenv global 3.10.13 && pip3 install --no-cache-dir -r /tmp/requirements.txt