# Last modified: 2023-11-23T00:13:10.301105+00:00
FROM cimg/python:3.12

# install docker
#RUN apt-get remove -y docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc && \
# curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg  && \
#    chmod a+r /etc/apt/keyrings/docker.gpg && echo \
#  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
#  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && apt-get update && \
#    apt-get install -y docker-ce docker-ce-cli containerd.io && apt-get purge -y docker-compose-plugin docker-buildx-plugin && docker --version

# Setup pyenv
RUN pyenv install -s 2.7.18 && pyenv versions | grep 2.7.18 && \
 pyenv install -s 3.9.16 && pyenv versions | grep 3.9.16 && \
 pyenv install -s 3.10.13 && pyenv versions | grep 3.10.13 && \
 pyenv install -s 3.11.0 && pyenv versions | grep 3.11.0 && \
 pyenv install -s 3.12.0 && pyenv versions | grep 3.12.0

COPY requirements.txt .

RUN pip3 install --no-cache-dir -r requirements.txt && pyenv global 3.10.13
RUN rm -rf /var/lib/apt/lists/*

