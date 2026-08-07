# Last modified: 2026-08-05T04:51:08.023163+00:00
FROM demisto/python3-deb-bullseye:3.12.11.10786156

WORKDIR "/app"

SHELL ["/bin/bash", "-c"]
RUN apt-get update -y -q && \
    apt-get upgrade -y -q && \
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
    fonts-ipafont-mincho \
    fonts-ipafont-gothic \
    fonts-unfonts-core \
    fonts-noto-cjk \
    fonts-noto-core \
    libgbm-dev \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g npm@8.19.4

# This line can be removed after puppeteer will update the brace-expansion in their side to >=5.0.8
# https://github.com/puppeteer/puppeteer/blob/main/package-lock.json
RUN echo '{"name":"app","version":"1.0.0","overrides":{"brace-expansion":"5.0.8"}}' > package.json && \
    npm install puppeteer@5.3.1 && \
    ln -s /app/node_modules/puppeteer/.local-chromium/linux-*/chrome-linux/chrome /usr/bin/chromium-browser
# install gsutil acc to https://cloud.google.com/storage/docs/gsutil_install
RUN apt-get update -y -q && apt-get install -y -q apt-transport-https ca-certificates gnupg curl \
    && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && apt-get update -y && apt-get install google-cloud-sdk -y


RUN gsutil cp -r gs://sane-reports-artifacts/sane-report.tar . \
    && tar -xvf sane-report.tar && rm -f sane-report.tar

# Update permissions and ownership on /app dir
RUN chown -R root:demisto /app/ && chmod 775 /app/ && chmod 775 /app/dist

RUN npm uninstall -g npm && apt-get purge -y --auto-remove git npm apt-transport-https ca-certificates gnupg curl google-cloud-sdk \
    python3-dev lsb-release \
    && rm -rf /var/lib/apt/lists/*
