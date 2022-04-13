FROM docker.art.code.pan.run/build-tools--image-ubuntu:18.04.ep1

RUN apt-get update && apt-get upgrade -y

RUN apt-get install -y --no-install-recommends --no-install-suggests gcc wget curl make \
    libreadline-dev libsqlite3-dev libbz2-dev software-properties-common \
    libssl-dev rsync unzip git wget  curl jq zip psmisc \
    aptitude build-essential rpm makeself apt-transport-https \
    ca-certificates gnupg bzip2 openssh-client libxml2-dev \
    libxslt1-dev libxslt-dev zlib1g-dev libxmlsec1 xmlsec1 \
    libxml2-dev libxmlsec1-dev libxmlsec1-openssl pcregrep

RUN curl -fsSL -O https://download.docker.com/linux/static/stable/x86_64/docker-19.03.9.tgz && \
    tar xf docker-19.03.9.tgz && \
    mv docker/* /usr/bin/ && \
    rm -rf docker-19.03.9.tgz docker

RUN groupadd circleci && groupadd docker \
  && useradd --shell /bin/bash --create-home ubuntu \
  && usermod -aG circleci ubuntu && usermod -aG docker ubuntu

RUN \
  export GOROOT=/usr/local/go && export PATH=$PATH:$GOROOT/bin && \
  curl -o go.tar.gz https://storage.googleapis.com/golang/go1.13.linux-amd64.tar.gz && \
  tar -C /usr/local -xzf go.tar.gz

RUN \
  echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | \
  tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
  curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - && \
  apt-get update && apt-get install -y --force-yes google-cloud-sdk

RUN \
  apt-get install -y --force-yes dnsutils

USER ubuntu

CMD /bin/bash
