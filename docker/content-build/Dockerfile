FROM cimg/python:3.10.1-node

RUN sudo apt-get update && \
  sudo apt-get install -y --no-install-recommends libxml2-dev libxslt1-dev zlib1g-dev jq \
  make cowsay build-essential libssl-dev libbz2-dev \
  libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
  xz-utils tk-dev libffi-dev liblzma-dev python-openssl

# install gcloud see: https://cloud.google.com/sdk/docs/downloads-apt-get
RUN sudo apt-get update && sudo apt-get install apt-transport-https ca-certificates gnupg \
  && curl -sSL https://install.python-poetry.org | python3 - \
  && export PATH="$HOME/.local/bin:$PATH >> ~/.bashrc" \
  && source ~/.bashrc \
  && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
  && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - \
  && sudo apt-get update && sudo apt-get install google-cloud-sdk \
  && gcloud --version \
  && gsutil --version  \
  && poetry --version
