FROM cimg/python:3.10-node

ENV DEBIAN_FRONTEND noninteractive
# install gcloud see: https://cloud.google.com/sdk/docs/downloads-apt-get
# install poetry see: https://python-poetry.org/docs/#installation
RUN sudo apt-get update \ 
  && sudo apt-get install apt-transport-https ca-certificates gnupg \
  && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
  && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - \
  && sudo apt-get update && sudo apt-get install google-cloud-cli \
  && sudo curl -sSL https://install.python-poetry.org | python3 - \
  && gcloud --version \
  && gsutil --version  \
  && poetry --version \
  && sudo apt-get remove docker docker-engine docker.io containerd runc \
  && sudo apt-get update \
  && sudo apt-get install ca-certificates curl gnupg \
  && sudo apt-get update \
  && sudo mkdir -m 0755 -p /etc/apt/keyrings \
  && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
  && echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null \
  && sudo apt-get update \
  && sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

