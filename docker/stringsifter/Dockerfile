FROM demisto/python3-deb:3.10.5.31873

# Configure Poetry
ENV POETRY_VERSION=1.5.1
ENV POETRY_HOME=/opt/poetry
ENV POETRY_VENV=/opt/poetry-venv
ENV POETRY_CACHE_DIR=/opt/.cache

# Install poetry separated from system interpreter
RUN python3 -m venv $POETRY_VENV \
    && $POETRY_VENV/bin/pip install -U pip setuptools \
    && $POETRY_VENV/bin/pip install poetry==${POETRY_VERSION}

# Add `poetry` to PATH
ENV PATH="${PATH}:${POETRY_VENV}/bin"

COPY pyproject.toml pyproject.toml
COPY poetry.lock poetry.lock

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends python3-dev make gcc g++ wget git libgomp1 \
  && /usr/bin/poetry config virtualenvs.create false \
  && poetry install --no-interaction \
  && rm -rf /root/.cache/pypoetry \
  && apt-get purge -y --auto-remove gcc g++ make python3-dev

