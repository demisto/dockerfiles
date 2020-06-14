
FROM demisto/python3-deb:3.8.2.6981

WORKDIR "/app"

SHELL ["/bin/bash", "-c"]
RUN apt-get update -y -q && \
    apt-get install -y -q sudo
RUN adduser --disabled-password --gecos '' docker && \
    adduser docker sudo && \
    echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER docker
RUN sudo apt-get install -y nodejs npm gconf-service \
    libasound2 libatk1.0-0 libatk-bridge2.0-0 \
    libc6 libcairo2 libcups2 libdbus-1-3 \
    libexpat1 libfontconfig1 libgcc1 \
    libgconf-2-4 libgdk-pixbuf2.0-0 \
    libglib2.0-0 libgtk-3-0 libnspr4 \
    libpango-1.0-0 libpangocairo-1.0-0 \
    libstdc++6 libx11-6 libx11-xcb1 libxcb1 \
    libxcomposite1 libxcursor1 libxdamage1 \
    libxext6 libxfixes3 libxi6 libxrandr2 \
    libxrender1 libxss1 libxtst6 \
    ca-certificates fonts-liberation \
    libappindicator1 libnss3 lsb-release \
    xdg-utils

RUN sudo npm install svgexport -g --unsafe-perm=true
RUN sudo mkdir sandbox && sudo chown docker:docker sandbox
COPY src sandbox/
WORKDIR sandbox
COPY requirements.txt .
RUN pip install -r requirements.txt && pip install -e .
