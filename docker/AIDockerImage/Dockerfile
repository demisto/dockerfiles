# Base image
FROM demisto/python3:3.12.8.1983910

# Copy dependency files
COPY pyproject.toml poetry.lock /

# Install dependencies using poetry
RUN pip install --no-cache-dir poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-root --no-dev

# Set the working directory
WORKDIR /
