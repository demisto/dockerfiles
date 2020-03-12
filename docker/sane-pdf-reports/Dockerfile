FROM node:10-slim

RUN apt-get update -y -q
RUN apt-get install -y make build-essential libssl-dev zlib1g-dev libbz2-dev \
    libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
    xz-utils tk-dev libffi-dev liblzma-dev
RUN wget https://www.python.org/ftp/python/3.6.9/Python-3.6.9.tgz
RUN tar xvf Python-3.6.9.tgz && cd Python-3.6.9 && ./configure && make && make install
WORKDIR "/app"
COPY ./dist ./dist
COPY ./reportsServer .
COPY ./reportsServer.js .
RUN npm i puppeteer@1.2.0
SHELL ["/bin/bash", "-c"]
RUN ln -s /app/node_modules/puppeteer/.local-chromium/linux-*/chrome-linux/chrome /usr/bin/chromium-browser
RUN apt-get install -y -q gconf-service libasound2 libatk1.0-0 libatk-bridge2.0-0 libc6 libcairo2 libcups2 libdbus-1-3 libexpat1 libfontconfig1 libgcc1 libgconf-2-4 libgdk-pixbuf2.0-0 libglib2.0-0 libgtk-3-0 libnspr4 libpango-1.0-0 libpangocairo-1.0-0 libstdc++6 libx11-6 libx11-xcb1 libxcb1 libxcomposite1 libxcursor1 libxdamage1 libxext6 libxfixes3 libxi6 libxrandr2 libxrender1 libxss1 libxtst6 ca-certificates fonts-liberation libappindicator1 libnss3 lsb-release xdg-utils wget
