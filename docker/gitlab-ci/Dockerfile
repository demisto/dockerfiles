FROM ubuntu:14.04

RUN apt-get update && apt-get upgrade -y

RUN apt-get install -y --no-install-recommends --no-install-suggests gcc wget curl make \
    libreadline-dev libsqlite3-dev libbz2-dev software-properties-common \
    libssl-dev rsync unzip git wget  curl jq zip psmisc \
    aptitude build-essential rpm makeself apt-transport-https \
    ca-certificates gnupg bzip2 openssh-client libxml2-dev \
    libxslt1-dev libxslt-dev zlib1g-dev libxmlsec1 xmlsec1 \
    libxml2-dev libxmlsec1-dev libxmlsec1-openssl pcregrep

RUN wget -k https://www.python.org/ftp/python/2.7.12/Python-2.7.12.tgz && \
    tar -zxvf Python-2.7.12.tgz && cd Python-2.7.12 && ./configure && make -j && make install && \
    curl -k https://bootstrap.pypa.io/2.7/get-pip.py -o get-pip.py && \
    python get-pip.py pip==20.2.2

RUN curl -fsSL -O https://download.docker.com/linux/static/stable/x86_64/docker-19.03.9.tgz && \
    tar xf docker-19.03.9.tgz && \
    mv docker/* /usr/bin/ && \
    rm -rf docker-19.03.9.tgz docker

RUN groupadd circleci && groupadd docker \
  && useradd --shell /bin/bash --create-home ubuntu \
  && usermod -aG circleci ubuntu && usermod -aG docker ubuntu \
  && echo 'ubuntu ALL=NOPASSWD: ALL' >> /etc/sudoers.d/50-ubuntu

RUN wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add - && \
    add-apt-repository "deb https://artifacts.elastic.co/packages/7.x/apt stable main" && \
    apt-get update

RUN \
  rm -rf /var/lib/apt/lists/* && \
  curl -L https://github.com/sstephenson/ruby-build/archive/v20180329.tar.gz | tar -zxvf - -C /tmp/ && \
  cd /tmp/ruby-build-* && ./install.sh && cd / && \
  ruby-build -v 2.5.1 /usr/local && rm -rfv /tmp/ruby-build-* && \
  gem install bundler --no-rdoc --no-ri

RUN \
  pip install --upgrade pip && \
  pip install stix --upgrade && pip install boto3 && \
  apt-get update && apt-get install -y chromium-browser && \
  add-apt-repository ppa:openjdk-r/ppa && apt-get update && apt-get -y install openjdk-11-jre --force-yes && \
  add-apt-repository --remove ppa:openjdk-r/ppa

RUN \
  export GOROOT=/usr/local/go && export PATH=$PATH:$GOROOT/bin && \
  curl -o go.tar.gz https://storage.googleapis.com/golang/go1.16.linux-amd64.tar.gz && \
  tar -C /usr/local -xzf go.tar.gz

RUN \
  wget -q https://github.com/google/protobuf/releases/download/v3.6.1/protoc-3.6.1-linux-x86_64.zip && \
  sudo unzip protoc-3.6.1-linux-x86_64.zip -d /usr/local && \
  rm protoc-3.6.1-linux-x86_64.zip

RUN \
  echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | \
  tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
  curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - && \
  apt-get update && apt-get install -y --force-yes google-cloud-sdk

RUN \
  apt-get install -y --force-yes dnsutils

USER ubuntu

CMD /bin/bash
