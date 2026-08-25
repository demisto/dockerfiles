# Last modified: 2026-08-25T01:52:15.769861+00:00
FROM demisto/python3-deb:3.12.13.12042988

WORKDIR /content

# Cache bust attempt 6

ADD https://raw.githubusercontent.com/demisto/demisto-sdk/master/package.json /content/
ADD https://raw.githubusercontent.com/demisto/demisto-sdk/master/package-lock.json /content/

ADD requirements.txt .


RUN apt-get update && apt-get -y --no-install-recommends upgrade && apt-get install \
    git \
    gcc \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    make \
    build-essential \
    libssl-dev zlib1g-dev libbz2-dev \
    libreadline-dev libsqlite3-dev wget llvm libncurses5-dev libncursesw5-dev \
    xz-utils tk-dev libffi-dev liblzma-dev zsh \
    libffi-dev python3-dev gfortran g++ pkg-config libhdf5-dev \
    -y \
    # install node - node distributions: https://github.com/nodesource/distributions
    && curl -fsSL https://deb.nodesource.com/setup_24.x | bash - \
    && apt update \
    && apt-get install -y nodejs \
    # install docker
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update && apt-get install docker-ce-cli -y \
    && python3 -m pip install --no-cache-dir -r requirements.txt \
    && python3 -m pip install --no-cache-dir gitpython>=3.1.48 cryptography>=50.0.0 nltk>=3.10.0 protobuf>=6.33.5 soupsieve>=2.8.4 ujson>=5.12.1 urllib3>=2.6.3 orjson>=3.11.5 \
    && npm install -g npm@latest \
    && npm ci \
    && npm install brace-expansion@^5.0.8 ip-address@^10.3.1 tar@^7.5.21 linkify-it@^5.0.2 @hapi/content@^6.0.1 \
    && npm install -g jsdoc-to-markdown@9.1.3\
    && npm list \
    && demisto-sdk --version

# Default demisto-sdk help
CMD ["demisto-sdk", "--help"]
