
FROM demisto/python3-deb:3.9.6.22912

RUN apt-get update && apt-get install ssdeep \
    && apt-get purge -y --auto-remove \
    && rm -rf /var/lib/apt/lists/*
