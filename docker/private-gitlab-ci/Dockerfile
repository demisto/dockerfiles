FROM centos:centos8.3.2011

RUN yum install -y curl && \
  export GOROOT=/usr/local/go && export PATH=$PATH:$GOROOT/bin && \
  curl -o go.tar.gz https://storage.googleapis.com/golang/go1.13.4.linux-amd64.tar.gz && \
  tar -C /usr/local -xzf go.tar.gz && \
  dnf module install nodejs:10 -y

CMD /bin/bash
