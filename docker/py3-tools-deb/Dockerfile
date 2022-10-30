# This is a py-tools image that is based on debian linux
FROM demisto/python3-deb:3.10.8.36615

ADD pyproject.toml .
ADD poetry.lock .

ENV PATH /root/.local/bin:$PATH

RUN apt-get update && apt-get install -y build-essential wget git libffi-dev \
    && curl -sSL https://install.python-poetry.org | python3 - \
    && poetry install