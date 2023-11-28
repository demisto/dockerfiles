# Last modified: 2023-11-23T00:13:10.301105+00:00
FROM cimg/python:3.12
#COPY requirements.txt .
#COPY localtime /etc/localtime
#RUN set -ex; apt-get update; apt-get install -y --no-install-recommends autoconf automake bzip2 dpkg-dev file g++ gcc  \
#    imagemagick libbz2-dev libc6-dev libcurl4-openssl-dev libdb-dev libevent-dev libffi-dev libgdbm-dev libglib2.0-dev \
#    libgmp-dev libjpeg-dev libkrb5-dev liblzma-dev libmagickcore-dev libmagickwand-dev libmaxminddb-dev libncurses5-dev  \
#    libncursesw5-dev libpng-dev libreadline-dev libssl-dev libtool libwebp-dev libxml2-dev  \
#    libxslt-dev libyaml-dev make patch unzip xz-utils zlib1g-dev
#RUN  apt-get install -y git mercurial xvfb apt locales sudo openssh-client ca-certificates tar gzip  \
#    parallel net-tools unzip zip bzip2 gnupg curl wget build-essential jq libgbm1
# install docker
#RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg  && \
#    chmod a+r /etc/apt/keyrings/docker.gpg && echo \
#  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
#  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && apt-get update && \
#    apt-get install -y docker-ce docker-ce-cli containerd.io && apt-get purge -y docker-compose-plugin docker-buildx-plugin && docker --version
# Setup pyenv + poetry and install extra python versions

RUN pyenv install -s 2.7.18 && pyenv versions | grep 2.7.18 && \
 pyenv install -s 3.9.16 && pyenv versions | grep 3.9.16 && \
 pyenv install -s 3.10.13 && pyenv versions | grep 3.10.13 && \
 pyenv install -s 3.11.0 && pyenv versions | grep 3.11.0 && \
 pyenv install -s 3.12.0 && pyenv versions | grep 3.12.0


RUN pip3 install --no-cache-dir -r requirements.txt && pyenv global 3.10.0
RUN rm -rf /var/lib/apt/lists/*

