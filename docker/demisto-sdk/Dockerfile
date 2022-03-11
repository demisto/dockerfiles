FROM demisto/python3-deb:3.10.1.26968

SHELL ["/bin/bash", "-c"]

ADD panw-cert.pem /usr/local/share/ca-certificates
RUN chmod 644 /usr/local/share/ca-certificates/panw-cert.pem && update-ca-certificates


RUN apt-get update && apt-get install \
    git \ 
    gcc \
    nodejs \
    npm \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    -y 

# Docker cli tools installation
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update && apt-get install docker-ce-cli -y


WORKDIR /content


# Install node modules for readme validation in demisto-sdk validate
ADD https://raw.githubusercontent.com/demisto/demisto-sdk/master/package.json /content/
ADD https://raw.githubusercontent.com/demisto/demisto-sdk/master/package-lock.json /content/

# Python requirements
ADD requirements.txt .
RUN npm ci && python3 -m pip install --no-cache-dir -r requirements.txt && rm requirements.txt

ADD https://raw.githubusercontent.com/demisto/content/master/dev-requirements-py3.txt /content/dev-requirements-py3.txt
ADD https://raw.githubusercontent.com/demisto/content/master/dev-requirements-py2.txt /content/dev-requirements-py2.txt

ADD bootstrap /content/bootstrap
RUN NO_HOOKS=1 SETUP_PY2=yes FORCE_SETUP=yes NO_NPM=true ./bootstrap && rm bootstrap && source venv/bin/activate

ENV PATH="/content/venv/bin:$PATH"

# apt-get Cleanup
RUN apt-get autoremove -y \
    && apt-get purge gcc -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Default demisto-sdk help
CMD ["demisto-sdk", "--help"]