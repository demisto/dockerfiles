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
  && poetry --version
