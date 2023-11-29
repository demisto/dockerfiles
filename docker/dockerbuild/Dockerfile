# Last modified: 2023-11-23T00:13:10.301105+00:00
FROM cimg/python:3.12

USER root
# install docker
RUN apt-get update && \
apt-get install ca-certificates curl gnupg && \
install -m 0755 -d /etc/apt/keyrings && \
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
chmod a+r /etc/apt/keyrings/docker.gpg && \
echo \
"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian/ \
$(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
tee /etc/apt/sources.list.d/docker.list > /dev/null && \
apt-get update & apt-get install -y docker-ce docker-ce-cli containerd.io && rm -rf /var/lib/apt/lists/*

USER circleci
COPY requirements.txt .

# Setup pyenv
RUN pyenv install -s 2.7.18 && pyenv versions | grep 2.7.18 && \
 pyenv install -s 3.9.16 && pyenv versions | grep 3.9.16 && \
 pyenv install -s 3.10.13 && pyenv versions | grep 3.10.13 && \
 pyenv install -s 3.11.0 && pyenv versions | grep 3.11.0 && \
 pyenv install -s 3.12.0 && pyenv versions | grep 3.12.0 && \
pyenv global 3.10.13 && pip3 install --no-cache-dir -r requirements.txt


