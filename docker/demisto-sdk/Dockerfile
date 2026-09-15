# Last modified: 2026-09-15T08:57:29.422633+00:00
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
    && ARCH=$(uname -m) && if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then ARCH="aarch64"; else ARCH="x86_64"; fi \
    && curl -fsSL "https://download.docker.com/linux/static/stable/$ARCH/docker-27.5.1.tgz" | tar xz \
    && mv docker/docker /usr/local/bin/ \
    && rm -rf docker \
    && python3 -m pip install --no-cache-dir -r requirements.txt \
    && npm install -g npm@latest \
    # npm bundles its own copies of tar and ip-address (via socks); package
    # overrides cannot reach them, so replace them in place. Unpack everything
    # before swapping, since npm itself needs tar to run.
    && NPM_BUNDLE="$(npm root -g)/npm/node_modules" \
    && mkdir -p /tmp/npmfix \
    && for dep in tar:7.5.22 ip-address:10.7.1; do \
        name="${dep%:*}"; version="${dep#*:}"; \
        mkdir -p "/tmp/npmfix/$name" \
        && curl -fsSL "https://registry.npmjs.org/$name/-/$name-$version.tgz" \
           | tar xz -C "/tmp/npmfix/$name" --strip-components=1; \
       done \
    && for name in tar ip-address; do \
        rm -rf "$NPM_BUNDLE/$name" && mv "/tmp/npmfix/$name" "$NPM_BUNDLE/$name"; \
       done \
    && rm -rf /tmp/npmfix \
    # Rename the project away from "content": that name collides with the
    # public npm package of the same name, so the CVE scan reports its
    # advisories (e.g. CVE-2026-35213, actually @hapi/content) against this
    # private dependency manifest.
    && node -e "const fs=require('fs'); const pkg=JSON.parse(fs.readFileSync('./package.json')); pkg.name='demisto-sdk-content-deps'; pkg.private=true; pkg.dependencies={...pkg.dependencies, 'jsdoc-to-markdown':'9.1.3'}; pkg.overrides={...pkg.overrides, 'ip-address':'>=10.3.1', 'tar':'>=7.5.21', 'linkify-it':'>=5.0.1', '@hapi/content':'>=6.0.1'}; fs.writeFileSync('./package.json', JSON.stringify(pkg));" \
    && npm install --package-lock-only \
    && npm ci \
    && ln -s /content/node_modules/.bin/jsdoc2md /usr/local/bin/jsdoc2md \
    && npm list \
    && demisto-sdk --version

# Default demisto-sdk help
CMD ["demisto-sdk", "--help"]
