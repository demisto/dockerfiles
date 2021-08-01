
FROM demisto/python3-deb:3.9.6.22912

COPY requirements.txt .

RUN apt-get update && apt-get install \
    build-essential \
    libffi-dev python3 python3-dev python3-pip automake autoconf libtool libfuzzy-dev \
    -y \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y --auto-remove \
    && rm -rf /var/lib/apt/lists/*
