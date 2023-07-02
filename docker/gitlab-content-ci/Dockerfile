FROM demisto/python3-deb:3.10.11.61745

ENV NODE_VERSION 14.14.0
ENV NVM_DIR /root/.nvm
ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:/root/.local/bin:$PATH
ENV NEO4J_CONF_FILE /etc/neo4j/neo4j.conf
ENV APOC_CONF_FILE /etc/neo4j/apoc.conf

# Currently sh is linked to dash, linking it to /bin/bash instead.
RUN rm /bin/sh && ln -s /bin/bash /bin/sh && cp ~/.profile ~/.bash_profile

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y curl jq unzip openssh-client gcc libffi-dev libssl-dev git zip cowsay netcat wget python2 python3-pip software-properties-common
RUN curl https://raw.githubusercontent.com/nvm-sh/nvm/v0.38.0/install.sh | bash \
    && . $NVM_DIR/nvm.sh \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default

# Installing the gsutil cli
RUN apt-get install apt-transport-https ca-certificates gnupg gpgv -y --allow-downgrades\
    && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" |  tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - \
    && apt-get update && apt-get install google-cloud-sdk -y && source ~/.bashrc && gsutil --version && gcloud --version

# Installing the docker cli
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - \
    && add-apt-repository "deb https://download.docker.com/linux/ubuntu bionic stable" \
    && apt-get update \
    && apt-get install docker-ce-cli -y && source ~/.bashrc && docker --version
RUN apt-get install kubectl -y && source ~/.bashrc && ! kubectl version --output yaml

# installations
RUN apt-get install openjdk-11-jre -y && source ~/.bashrc && java -version
RUN curl -sSL https://install.python-poetry.org | python3 - && source ~/.bashrc && poetry --version

# install neo4j
RUN echo "deb http://httpredir.debian.org/debian stable-backports main" | tee -a /etc/apt/sources.list.d/stable-backports.list \
    && wget -O - https://debian.neo4j.com/neotechnology.gpg.key | apt-key add - \
    && echo 'deb https://debian.neo4j.com stable 5' | tee -a /etc/apt/sources.list.d/neo4j.list \
    && apt-get update
RUN mkdir -p /var/lib/neo4j/plugins \
    && wget -O /var/lib/neo4j/plugins/apoc-5.5.0-core.jar https://github.com/neo4j/apoc/releases/download/5.5.0/apoc-5.5.0-core.jar \
    && apt-get install neo4j -y && source ~/.bashrc && neo4j --version && neo4j-admin --version \
    && neo4j_conf_file="/etc/neo4j/neo4j.conf" \
    && echo "dbms.security.procedures.unrestricted=apoc.*" >> $NEO4J_CONF_FILE \
    && echo "dbms.security.procedures.allowlist=apoc.*" >> $NEO4J_CONF_FILE \
    && apoc_conf_file="/etc/neo4j/apoc.conf" \
    && echo "apoc.export.file.enabled=true" > $APOC_CONF_FILE \
    && echo "apoc.import.file.enabled=true" >> $APOC_CONF_FILE \
    && echo "apoc.import.file.use_neo4j_config=true" >> $APOC_CONF_FILE
# Installing goenv
RUN git clone https://github.com/syndbg/goenv.git ~/.goenv \
    && echo 'export GOENV_ROOT="$HOME/.goenv"' >> ~/.bashrc \
    && echo 'export PATH="$GOENV_ROOT/bin:$PATH"' >> ~/.bashrc \
    && echo 'export PATH="$GOROOT/bin:$PATH"' >> ~/.bashrc \
    && echo 'export PATH="$PATH:$GOPATH/bin"' >> ~/.bashrc
RUN source ~/.bashrc \
    && goenv install 1.20rc2 \
    && goenv global 1.20rc2 \
    && echo 'eval "$(goenv init -)"' >> ~/.bashrc \
    && source ~/.bashrc
RUN curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.47.3 
