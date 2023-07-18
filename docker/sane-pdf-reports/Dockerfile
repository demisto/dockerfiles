# Last modified: 2023-07-18T16:39:17.578206+00:00
FROM demisto/python3-deb:3.10.12.65454

WORKDIR "/app"

COPY ./get_build_artifacts.py .

SHELL ["/bin/bash", "-c"]
RUN apt-get update -y -q && \
    apt-get install -y -q nodejs \
    npm gconf-service \
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
    libnss3 lsb-release \
    xdg-utils wget locales \
    fonts-arphic-ukai fonts-arphic-uming \
    fonts-ipafont-mincho fonts-ipafont-gothic \
    fonts-unfonts-core \
    fonts-noto-cjk \
    fonts-noto-core \
    libgbm-dev \
    && rm -rf /var/lib/apt/lists/* \
    && npm i npm@8.1.3 -g

RUN npm i puppeteer@5.3.1 && ln -s /app/node_modules/puppeteer/.local-chromium/linux-*/chrome-linux/chrome /usr/bin/chromium-browser

RUN python get_build_artifacts.py --project sane-reports --branch master --filter "sane-report$" \
    && mv sane-report sane-report.tar && tar -xvf sane-report.tar && rm -f sane-report.tar

# Update permissions and ownership on /app dir
RUN chown -R root:demisto /app/ && chmod 775 /app/ && chmod 775 /app/dist

RUN apt-get purge -y --auto-remove git npm \
    && rm -rf /var/lib/apt/lists/*