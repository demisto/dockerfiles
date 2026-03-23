FROM demisto/python3-deb:3.12.13.7742802

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    wget \
    unzip \
    chromium \
 && wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip -O aquatone.zip \
 && unzip aquatone.zip -d /usr/local/bin/ \
 && rm aquatone.zip \
 && apt-get purge -y --auto-remove \
    wget \
    unzip \
 && rm -rf /var/lib/apt/lists/*