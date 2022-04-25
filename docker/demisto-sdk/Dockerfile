FROM demisto/python3-deb:3.10.4.28391

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

# Install content dev-dependencies. Create virtual envs for python2 and python3
ADD https://raw.githubusercontent.com/demisto/content/master/dev-requirements-py3.txt /content/dev-requirements-py3.txt
ADD https://raw.githubusercontent.com/demisto/content/master/dev-requirements-py2.txt /content/dev-requirements-py2.txt

RUN virtualenv -p python2 venv \
    && venv/bin/pip2 install -r dev-requirements-py2.txt \
    && python3 -m venv --system-site-packages venv \
    && venv/bin/pip3 install -r dev-requirements-py3.txt -U --upgrade-strategy only-if-needed \
    && rm /content/dev-requirements-py2.txt /content/dev-requirements-py3.txt

ENV PATH="/content/venv/bin:$PATH"

# apt-get Cleanup
RUN apt-get autoremove -y \
    && apt-get purge gcc -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

# Default demisto-sdk help
CMD ["demisto-sdk", "--help"]