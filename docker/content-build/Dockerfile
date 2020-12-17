FROM circleci/python:3.8.5-buster-node

RUN sudo apt-get update && \
  sudo apt-get install -y --no-install-recommends python-dev libxml2-dev libxslt1-dev zlib1g-dev python-setuptools jq \
  make build-essential libssl-dev libbz2-dev \
  libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
  xz-utils tk-dev libffi-dev liblzma-dev python-openssl \
  python3 python3-dev && sudo pip3 install --no-cache-dir -r requirements.txt

# Change virtualenv version to old version - Bug with link 2 python versions
RUN sudo pip3 uninstall -y virtualenv && sudo pip3 install virtualenv==16.7.7

# install gcloud see: https://cloud.google.com/sdk/docs/downloads-apt-get
RUN sudo apt-get update && sudo apt-get install apt-transport-https ca-certificates gnupg \
  && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
  && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - \
  && sudo apt-get update && sudo apt-get install google-cloud-sdk \
  && gcloud --version \
  && gsutil --version
