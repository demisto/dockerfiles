FROM ubuntu:18.04
SHELL [ "/bin/bash", "-c" ]

# Setup dockerfile env vars
ENV GO_VANILLA_TAR=go1.12.9.linux-amd64.tar.gz
ENV HOME=/root
ENV GOROOT_BOOTSTRAP=/tmp/go

# Setup linux env vars and directory structure
WORKDIR $HOME
RUN mkdir -p /root/dev/go
RUN echo "export GOROOT_BOOTSTRAP=/tmp/go\n\
export GOROOT=/usr/local/go\n\
export GOPATH=$HOME/dev/go\n\
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH\n\
alias sudo=\"\"" >> .bashrc
RUN source .bashrc

# Install dependencies
RUN apt-get update
RUN apt-get install -y git wget gcc autoconf automake libtool curl make g++ unzip libxml2-dev libxslt1-dev libxslt-dev zlib1g-dev libxmlsec1 xmlsec1 libxml2-dev libxmlsec1-dev libxmlsec1-openssl
# Excluded python-dev for now

# Get regular go (for go + boringcrypto compilation)
WORKDIR /tmp
RUN wget https://dl.google.com/go/${GO_VANILLA_TAR}
RUN tar -xvf ${GO_VANILLA_TAR}

# Get and build go + boringcrypto
WORKDIR /usr/local
# Cannot verify certificates behind ssl-inspector...
RUN git config --global http.sslVerify false
RUN git clone https://github.com/golang/go.git -b dev.boringcrypto.go1.12
RUN git config --global http.sslVerify true
WORKDIR /usr/local/go/src
RUN ./all.bash