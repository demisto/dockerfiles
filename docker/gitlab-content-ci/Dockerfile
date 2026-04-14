FROM python:3.14.4-slim-trixie

# ── Version pins (update these to bump tools) ──
ENV NODE_VERSION=24.14.1
ENV NVM_VERSION=0.40.4
ENV NEO4J_VERSION=2026.03.1
ENV APOC_VERSION=2026.03.1
ENV POETRY_VERSION=1.8.5
ENV GO_VERSION=1.26.2
ENV GOLANGCI_LINT_VERSION=2.11.4
ENV OPENJDK_VERSION=25

# ── Path & config ──
ENV NVM_DIR=/root/.nvm
ENV PATH=$NVM_DIR/versions/node/v$NODE_VERSION/bin:/root/.local/bin:$PATH
ENV NEO4J_CONF_FILE=/etc/neo4j/neo4j.conf
ENV APOC_CONF_FILE=/etc/neo4j/apoc.conf

# Currently sh is linked to dash, linking it to /bin/bash instead.
RUN rm /bin/sh && ln -s /bin/bash /bin/sh
RUN (test -f ~/.profile && cat ~/.profile >> /etc/.profile || true)

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    curl jq unzip openssh-client gcc libffi-dev libssl-dev git zip cowsay netcat-openbsd wget \
    apt-transport-https ca-certificates gnupg gpgv
RUN rm -rf /var/lib/apt/lists/*

# Node.js via NVM
RUN curl https://raw.githubusercontent.com/nvm-sh/nvm/v${NVM_VERSION}/install.sh | bash
RUN . $NVM_DIR/nvm.sh \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default
RUN npm install -g npm@latest picomatch@latest

# Google Cloud SDK
RUN curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee /etc/apt/sources.list.d/google-cloud-sdk.list
RUN apt-get update && apt-get install google-cloud-sdk google-cloud-sdk-gke-gcloud-auth-plugin -y
RUN rm -rf /var/lib/apt/lists/*
RUN source ~/.bashrc && gsutil --version
RUN source ~/.bashrc && gcloud --version

# Docker CLI and Kubectl
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker.gpg
RUN echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker.gpg] https://download.docker.com/linux/debian trixie stable" | tee /etc/apt/sources.list.d/docker.list
RUN apt-get update && apt-get install docker-ce-cli kubectl -y
RUN rm -rf /var/lib/apt/lists/*
RUN source ~/.bashrc && docker --version
RUN source ~/.bashrc && (! kubectl version --output yaml || true)

# Java & Python Poetry
RUN apt-get update && apt-get install openjdk-${OPENJDK_VERSION}-jre -y
RUN rm -rf /var/lib/apt/lists/*
RUN source ~/.bashrc && java -version
RUN curl -sSL https://install.python-poetry.org | python3 - --version ${POETRY_VERSION}
RUN source ~/.bashrc && poetry --version

# Neo4j + APOC plugin
RUN wget -O - https://debian.neo4j.com/neotechnology.gpg.key | gpg --dearmor -o /usr/share/keyrings/neo4j.gpg
RUN echo 'deb [signed-by=/usr/share/keyrings/neo4j.gpg] https://debian.neo4j.com stable latest' | tee /etc/apt/sources.list.d/neo4j.list
RUN apt-get update && apt-get install neo4j=1:${NEO4J_VERSION} -y
RUN rm -rf /var/lib/apt/lists/*
RUN mkdir -p /var/lib/neo4j/plugins
RUN wget -O /var/lib/neo4j/plugins/apoc-${APOC_VERSION}-core.jar https://github.com/neo4j/apoc/releases/download/${APOC_VERSION}/apoc-${APOC_VERSION}-core.jar
RUN source ~/.bashrc && neo4j --version
RUN source ~/.bashrc && neo4j-admin --version
RUN echo "dbms.security.procedures.unrestricted=apoc.*" >> $NEO4J_CONF_FILE
RUN echo "dbms.security.procedures.allowlist=apoc.*" >> $NEO4J_CONF_FILE
RUN echo "apoc.export.file.enabled=true" > $APOC_CONF_FILE
RUN echo "apoc.import.file.enabled=true" >> $APOC_CONF_FILE
RUN echo "apoc.import.file.use_neo4j_config=true" >> $APOC_CONF_FILE

# Go via goenv
RUN git clone https://github.com/go-nv/goenv.git --depth 1 ~/.goenv
RUN echo 'export GOENV_ROOT="$HOME/.goenv"' >> ~/.bashrc
RUN echo 'export PATH="$GOENV_ROOT/bin:$PATH"' >> ~/.bashrc
RUN source ~/.bashrc && goenv install ${GO_VERSION}
RUN source ~/.bashrc && goenv global ${GO_VERSION}
RUN echo 'eval "$(goenv init -)"' >> ~/.bashrc
RUN echo 'export PATH="$GOROOT/bin:$PATH"' >> ~/.bashrc
RUN echo 'export PATH="$PATH:$GOPATH/bin"' >> ~/.bashrc

# golangci-lint
RUN source ~/.bashrc
# RUN curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(source ~/.bashrc && go env GOPATH)/bin v${GOLANGCI_LINT_VERSION}
