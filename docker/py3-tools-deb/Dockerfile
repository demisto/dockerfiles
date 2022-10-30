# This is a py-tools image that is based on debian linux
FROM demisto/python3-deb:3.10.8.36615
ENV PATH /root/.local/bin:$PATH

ADD docker/py3-tools-deb/pyproject.toml .
ADD docker/py3-tools-deb/poetry.lock .

RUN apt-get update && apt-get install -y build-essential wget git libffi-dev \
    && curl -sSL https://install.python-poetry.org | python3 - \
    && poetry install