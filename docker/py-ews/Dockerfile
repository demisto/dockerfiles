FROM demisto/python3-deb:3.10.14.91136


# Copy requirements file
COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
    libxslt-dev \
    python3-dev \
    gcc \
    build-essential \
    wget \
    git \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y --auto-remove \
    python3-dev \
    gcc \
    build-essential \
    wget \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/cache/apt/*