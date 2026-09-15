# Last modified: 2026-09-15T08:05:48.192251+00:00
FROM demisto/python3-deb:3.12.14.13053055

WORKDIR /content


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
    && apt-get update && apt-get install docker-ce-cli -y && apt-get install --only-upgrade docker-ce-cli -y \
    && python3 -m pip install --no-cache-dir -r requirements.txt \
    && npm install -g npm@latest \
    && node -e "const fs=require('fs'); const pkg=JSON.parse(fs.readFileSync('./package.json')); pkg.overrides={...pkg.overrides, 'ip-address':'>=10.3.1', 'tar':'>=7.5.21', 'linkify-it':'>=5.0.1', '@hapi/content':'>=6.0.1'}; fs.writeFileSync('./package.json', JSON.stringify(pkg));" \
    && npm install --package-lock-only \
    && npm ci \
    && npm install -g jsdoc-to-markdown@latest \
    && npm list \
    && demisto-sdk --version

# Default demisto-sdk help
CMD ["demisto-sdk", "--help"]
