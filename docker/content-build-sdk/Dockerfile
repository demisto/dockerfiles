FROM circleci/python:3.8.1-buster-node

COPY package.json /
RUN sudo npm install --loglevel=error -g && sudo rm -f package.json
ENV DEMISTO_README_VALIDATION "True"

RUN sudo apt-get update && \
  sudo apt-get install -y --no-install-recommends python-dev libxml2-dev libxslt1-dev zlib1g-dev python-setuptools jq \
  make build-essential libssl-dev libbz2-dev \
  libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
  xz-utils tk-dev libffi-dev liblzma-dev python-openssl \
  python3 python3-dev
