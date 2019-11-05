FROM circleci/python:3.7.5-buster-node

RUN sudo apt-get update && \
  sudo apt-get install -y --no-install-recommends python-dev libxml2-dev libxslt1-dev zlib1g-dev python-setuptools jq \
  make build-essential libssl-dev libbz2-dev \
  libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
  xz-utils tk-dev libffi-dev liblzma-dev python-openssl \
  python3 python3-dev

RUN sudo npm install -g jsdoc-to-markdown@5.0.2
