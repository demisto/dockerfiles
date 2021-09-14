FROM demisto/python3-deb:3.9.1.14969

RUN apt-get update

RUN apt-get install -y curl jq unzip openssh-client gcc libffi-dev libssl-dev git zip netcat wget python2 python-pip

# Currently sh is linked to dash, linking it to /bin/bash instead
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

# Installing nvm, npm and node.js
ENV NODE_VERSION 12.18.4
RUN \
    curl https://raw.githubusercontent.com/creationix/nvm/v0.38.0/install.sh | bash \
    && export NVM_DIR="$HOME/.nvm" \
    && export NODE_VERSION="12.18.4" \
    && . $NVM_DIR/nvm.sh \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default

ENV NVM_DIR ~/.nvm
ENV NODE_PATH $NVM_DIR/versions/node/v$NODE_VERSION/lib/node_modules
ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Instaling the gsutil
RUN  apt-get update -y \
  && apt-get install apt-transport-https ca-certificates gnupg=2.2.12-1+deb10u1 gpgv=2.2.12-1+deb10u1 -y --allow-downgrades\
  && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" |  tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
  && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - \
  &&  apt-get update &&  apt-get install google-cloud-sdk -y\
  && gcloud --version \
  && gsutil --version


