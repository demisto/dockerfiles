# Last modified: 2026-04-08T00:35:19.003711+00:00
FROM python:3.12.13-slim-bookworm

RUN echo 'deb http://deb.debian.org/debian bookworm-backports main' >> /etc/apt/sources.list

# Basic linux utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
  procps \
&& rm -rf /var/lib/apt/lists/*

# Upgrade all packages to latest
RUN apt-get update && apt-get -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

# Upgrade using backports
RUN apt-get update && apt-get -t bookworm-backports -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*


# Relevant for tldextract
COPY --chmod=644 public_list.dat /var/public_list.dat

#Install tools for building binary deps (will be reomved later on)
RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \ 
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/* \
&& pip install --upgrade setuptools \
&& pip install --upgrade wheel>=0.46.2

# Handling the issue described here https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000POJ0CAO&lang=en_US%E2%80%A9
# by enabling UnsafeLegacyRenegotiation
# We add to the openssl_init section after the last element "providers = provider_sect"
RUN cp /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.org && \ 
echo 'ssl_conf = ssl_sect\n\
[ssl_sect]\n\
system_default = system_default_sect\n\
\n\
[system_default_sect]\n\
Options = UnsafeLegacyRenegotiation\n' > /tmp/ssl.cnf \
&& sed -i '/providers = provider_sect/r /tmp/ssl.cnf' /etc/ssl/openssl.cnf \
&& rm /tmp/ssl.cnf \
&& grep -C 10 'Options = UnsafeLegacyRenegotiation' /etc/ssl/openssl.cnf

RUN groupadd --gid 4000 demisto \
  && useradd --uid 4000 --gid demisto --shell /bin/bash --create-home demisto

ENV NODE_VERSION 14.16.0
ENV NVM_DIR /root/.nvm
ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:/root/.local/bin:$PATH
ENV NEO4J_CONF_FILE /etc/neo4j/neo4j.conf
ENV APOC_CONF_FILE /etc/neo4j/apoc.conf

# Currently sh is linked to dash, linking it to /bin/bash instead.
RUN rm /bin/sh && ln -s /bin/bash /bin/sh && cat ~/.profile >> /etc/.profile

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get update && apt-get install -y curl jq unzip openssh-client gcc libffi-dev libssl-dev git zip cowsay netcat-openbsd wget python3-pip software-properties-common
# Upgrade Git to latest version from backports (already configured in base image)
RUN apt-get update && apt-get install -y git && git --version

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
RUN apt-get install google-cloud-sdk-gke-gcloud-auth-plugin -y && source ~/.bashrc

# installations
RUN apt-get install openjdk-17-jre -y && source ~/.bashrc && java -version
RUN curl -sSL https://install.python-poetry.org | python3 - --version 1.8.2 && source ~/.bashrc && poetry --version

# install neo4j
RUN echo "deb http://httpredir.debian.org/debian stable-backports main" | tee -a /etc/apt/sources.list.d/stable-backports.list \
    && wget -O - https://debian.neo4j.com/neotechnology.gpg.key | apt-key add - \
    && echo 'deb https://debian.neo4j.com stable 5' | tee -a /etc/apt/sources.list.d/neo4j.list \
    && apt-get update
RUN mkdir -p /var/lib/neo4j/plugins \
    && wget -O /var/lib/neo4j/plugins/apoc-5.26.0-core.jar https://github.com/neo4j/apoc/releases/download/5.26.0/apoc-5.26.0-core.jar \
    && apt-get install neo4j -y && source ~/.bashrc && neo4j --version && neo4j-admin --version \
    && neo4j_conf_file="/etc/neo4j/neo4j.conf" \
    && echo "dbms.security.procedures.unrestricted=apoc.*" >> $NEO4J_CONF_FILE \
    && echo "dbms.security.procedures.allowlist=apoc.*" >> $NEO4J_CONF_FILE \
    && apoc_conf_file="/etc/neo4j/apoc.conf" \
    && echo "apoc.export.file.enabled=true" > $APOC_CONF_FILE \
    && echo "apoc.import.file.enabled=true" >> $APOC_CONF_FILE \
    && echo "apoc.import.file.use_neo4j_config=true" >> $APOC_CONF_FILE
# Installing goenv
RUN git clone https://github.com/go-nv/goenv.git --depth 1 ~/.goenv
RUN echo 'export GOENV_ROOT="$HOME/.goenv"' >> ~/.bashrc \
    && echo 'export PATH="$GOENV_ROOT/bin:$PATH"' >> ~/.bashrc \ 
    && source ~/.bashrc \
    && goenv install 1.22.5 \
    && goenv global 1.22.5 \
    && echo 'eval "$(goenv init -)"' >> ~/.bashrc \
    && echo 'export PATH="$GOROOT/bin:$PATH"' >> ~/.bashrc \
    && echo 'export PATH="$PATH:$GOPATH/bin"' >> ~/.bashrc \
    && source ~/.bashrc
RUN curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.60.3

