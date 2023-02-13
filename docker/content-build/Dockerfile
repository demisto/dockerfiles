FROM cimg/python:3.10.10-node

ENV PATH $HOME/.local/bin:$PATH
ENV NEO4J_CONF_FILE /etc/neo4j/neo4j.conf
ENV APOC_CONF_FILE /etc/neo4j/apoc.conf

RUN sudo apt-get update && \
  sudo apt-get install -y --no-install-recommends libxml2-dev libxslt1-dev zlib1g-dev jq \
  make cowsay build-essential libssl-dev libbz2-dev \
  libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
  xz-utils tk-dev libffi-dev liblzma-dev python-openssl

# install gcloud see: https://cloud.google.com/sdk/docs/downloads-apt-get
RUN sudo apt-get update && sudo apt-get install apt-transport-https ca-certificates gnupg \
  && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
  && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - \
  && sudo apt-get update && sudo apt-get install google-cloud-sdk \
  && wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -\
  && echo 'deb https://debian.neo4j.com stable 4.4' | sudo tee -a /etc/apt/sources.list.d/neo4j.list \
  && sudo apt-get update \
  && sudo apt-get install neo4j -y \
  && sudo chown -R circleci /var/log/neo4j \
  && sudo chown -R circleci /var/lib/neo4j \
  && sudo chown -R circleci /etc/neo4j \
  && sudo echo "dbms.security.procedures.unrestricted=apoc.*" >> $NEO4J_CONF_FILE \
  && sudo echo "dbms.security.procedures.allowlist=apoc.*" >> $NEO4J_CONF_FILE \
  && apoc_conf_file="/etc/neo4j/apoc.conf" \
  && sudo echo "apoc.export.file.enabled=true" > $APOC_CONF_FILE \
  && sudo echo "apoc.import.file.enabled=true" >> $APOC_CONF_FILE \
  && sudo echo "apoc.import.file.use_neo4j_config=true" >> $APOC_CONF_FILE \
  && mkdir -p /var/lib/neo4j/plugins \
  && wget -O /var/lib/neo4j/plugins/apoc-4.4.0.8-all.jar https://github.com/neo4j-contrib/neo4j-apoc-procedures/releases/download/4.4.0.8/apoc-4.4.0.8-all.jar \
  && gcloud --version \
  && gsutil --version  \
  && poetry --version
