FROM demisto/python3:3.10.11.54132

RUN apk --update add curl &&  \
    curl -sSL --insecure https://install.python-poetry.org | python3 - && \
    export PATH="/root/.local/bin:$PATH"
