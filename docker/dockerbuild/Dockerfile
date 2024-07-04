# Last modified: 2023-11-23T00:13:10.301105+00:00
FROM cimg/python:3.12

USER root
# install docker

RUN sudo apt-get update  && \
sudo apt-get install -y ca-certificates curl gnupg libkrb5-dev automake python3-dev libtool && \
sudo install -m 0755 -d /etc/apt/keyrings && \
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
sudo chmod a+r /etc/apt/keyrings/docker.gpg && \
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null && \
sudo apt-get update && \
apt-get upgrade -y docker-ce docker-ce-cli docker-buildx-plugin containerd.io git  \
    && apt-get purge -y docker-compose-plugin docker-scan-plugin git-lfs && rm -rf /var/lib/apt/lists/*  \
    && rm /usr/local/bin/docker-compose /usr/local/bin/yq /usr/local/bin/compose-switch /usr/local/lib/docker/cli-plugins/docker-compose

USER circleci
COPY requirements.txt /tmp/requirements.txt

# Setup pyenv
RUN pyenv install -s 2.7.18 && pyenv versions | grep 2.7.18 && \
 pyenv install -s 3.8.15 && pyenv versions | grep 3.8.15 && \
 pyenv install -s 3.9.16 && pyenv versions | grep 3.9.16 && \
 pyenv install -s 3.10.13 && pyenv versions | grep 3.10.13 && \
 pyenv install -s 3.11.0 && pyenv versions | grep 3.11.0 && \
 pyenv install -s 3.12.0 && pyenv versions | grep 3.12.0 && \
pyenv global 3.10.13 && pip3 install --no-cache-dir -r /tmp/requirements.txt


