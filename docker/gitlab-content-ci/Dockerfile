FROM demisto/python3-deb:3.10.6.33421

ENV NODE_VERSION 14.14.0
ENV NVM_DIR /root/.nvm
ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:/root/.local/bin:$PATH

ADD neo4j.conf neo4j.conf
ADD apoc.conf apoc.conf

# Currently sh is linked to dash, linking it to /bin/bash instead.
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

RUN apt-get update  && apt-get upgrade -y \
    && apt-get install -y curl jq unzip openssh-client gcc libffi-dev libssl-dev git zip cowsay netcat wget python2 python3-pip software-properties-common \
    # Installing nvm, npm and node.js
    && curl https://raw.githubusercontent.com/nvm-sh/nvm/v0.38.0/install.sh | bash \
    && . $NVM_DIR/nvm.sh \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default \
    # Installing the gsutil and docker cli
    && apt-get install apt-transport-https ca-certificates gnupg gpgv -y --allow-downgrades\
    && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" |  tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - \
    && add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable" \
    # install neo4j
    && echo "deb http://httpredir.debian.org/debian stretch-backports main" | tee -a /etc/apt/sources.list.d/stretch-backports.list \
    && wget -O - https://debian.neo4j.com/neotechnology.gpg.key | apt-key add - \
    && echo 'deb https://debian.neo4j.com stable 4.4' | tee -a /etc/apt/sources.list.d/neo4j.list \
    && mkdir -p /var/lib/neo4j/plugins \
    && wget -O /var/lib/neo4j/plugins/apoc-4.4.0.8-all.jar https://github.com/neo4j-contrib/neo4j-apoc-procedures/releases/download/4.4.0.8/apoc-4.4.0.8-all.jar \
    && apt-get update && apt-get install google-cloud-sdk docker-ce-cli kubectl openjdk-11-jre neo4j -y \
    && cp neo4j /etc/neo4j/neo4j.conf && cp apoc.conf /etc/neo4j/apoc.conf \
    && curl -sSL https://install.python-poetry.org | python3 - \
    && source ~/.bashrc \
    && gsutil --version \
    && docker --version \
    && neo4j --version \
    && neo4j-admin --version \
    && gcloud --version \
    && ! kubectl version --output yaml \
    && poetry --version \
    # Installing goenv
    && git clone https://github.com/syndbg/goenv.git ~/.goenv \
    && echo 'export GOENV_ROOT="$HOME/.goenv"' >> ~/.bashrc \
    && echo 'export PATH="$GOENV_ROOT/bin:$PATH"' >> ~/.bashrc \
    && echo 'eval "$(goenv init -)"' >> ~/.bashrc \
    && echo 'export PATH="$GOROOT/bin:$PATH"' >> ~/.bashrc \
    && echo 'export PATH="$PATH:$GOPATH/bin"' >> ~/.bashrc \
    && source ~/.bashrc \
    && goenv install 1.13.8 \
    && goenv global 1.13.8 \
    && source ~/.bashrc \
    && curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.40.1
