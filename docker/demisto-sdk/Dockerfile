FROM demisto/python3-deb:3.10.1.26244

RUN apt-get update && apt install git gcc nodejs npm -y && rm -rf /var/lib/apt/lists/*

# Install node modules for readme validation in demisto-sdk validate
WORKDIR /content
COPY package*.json ./
RUN npm ci

# Do no run on root
USER demisto
WORKDIR /home/demisto

# Add pip installs to path with demisto user
ENV PYTHONPATH "${PYTHONPATH}:/home/demisto/.local/bin"
ENV PATH "${PATH}:/home/demisto/.local/bin"

# Install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Work in content folder
WORKDIR /content
