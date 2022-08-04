FROM cimg/python:3.10.5-node

RUN sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 648ACFD622F3D138 \
  && sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 0E98404D386FA1D9 \ 
  && sudo apt-get update && \
  sudo apt-get install -y --no-install-recommends libxml2-dev libxslt1-dev zlib1g-dev jq \
  make cowsay build-essential libssl-dev libbz2-dev \
  libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
  xz-utils tk-dev libffi-dev liblzma-dev python-openssl

# install gcloud see: https://cloud.google.com/sdk/docs/downloads-apt-get
RUN sudo apt-get update && sudo apt-get install apt-transport-https ca-certificates gnupg \
  && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
  && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - \
  # install neo4j
  && echo "deb http://httpredir.debian.org/debian stretch-backports main" | sudo tee -a /etc/apt/sources.list.d/stretch-backports.list \
  && wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add - \
  && wget -O /var/lib/neo4j/plugins/apoc-4.1.0.0-all.jar https://github.com/neo4j-contrib/neo4j-apoc-procedures/releases/download/4.1.0.0/apoc-4.1.0.0-all.jar \
  && echo 'deb https://debian.neo4j.com stable latest' | sudo tee -a /etc/apt/sources.list.d/neo4j.list \
  && sudo apt-get update && sudo apt-get install google-cloud-sdk kubectl openjdk-11-jre neo4j \
  && gcloud --version \
  && gsutil --version  \
  && poetry --version \
  && neo4j --version \
  && neo4j-admin --version
