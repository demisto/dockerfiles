FROM ubuntu:14.04

RUN apt-get update && apt-get upgrade -y

RUN apt-get install -y --no-install-recommends gcc wget curl make \
    libreadline-dev libsqlite3-dev libbz2-dev \
    libssl-dev rsync

RUN wget -k https://www.python.org/ftp/python/2.7.12/Python-2.7.12.tgz && \
    tar -zxvf Python-2.7.12.tgz && cd Python-2.7.12 && ./configure && make -j && make install && \
    curl -k https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
    python get-pip.py pip==20.2.2

RUN curl -fsSL -O https://download.docker.com/linux/static/stable/x86_64/docker-19.03.9.tgz && \
    tar xf docker-19.03.9.tgz && \
    mv docker/* /usr/bin/ && \
    rm -rf docker-19.03.9.tgz docker

RUN groupadd --gid 3434 circleci \
  && useradd --uid 3434 --gid circleci --shell /bin/bash --create-home circleci \
  && echo 'circleci ALL=NOPASSWD: ALL' >> /etc/sudoers.d/50-circleci

USER circleci

CMD /bin/bash
