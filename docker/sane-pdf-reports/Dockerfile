# Last modified: 2026-07-27T04:44:18.718308+00:00
FROM demisto/python3-deb-bullseye:3.12.11.10786156

WORKDIR "/app"

SHELL ["/bin/bash", "-c"]
# hadolint ignore=DL3008,DL3015,DL3027,DL3016
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

# hadolint ignore=DL3016,DL3059
RUN echo '{"name":"app","version":"1.0.0","overrides":{"brace-expansion":"5.0.8"}}' > package.json && \
    npm install puppeteer@5.3.1 && \
    ln -s /app/node_modules/puppeteer/.local-chromium/linux-*/chrome-linux/chrome /usr/bin/chromium-browser
# install gsutil acc to https://cloud.google.com/storage/docs/gsutil_install
# hadolint ignore=DL3008,DL3015,DL4006,DL3059,DL3009
RUN apt-get update -y -q && apt-get install -y -q apt-transport-https ca-certificates gnupg curl \
    && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && apt-get update -y && apt-get install google-cloud-sdk -y


# hadolint ignore=DL3059
RUN gsutil cp -r gs://sane-reports-artifacts/sane-report.tar . \
    && tar -xvf sane-report.tar && rm -f sane-report.tar

# Update permissions and ownership on /app dir
# hadolint ignore=DL3059
RUN chown -R root:demisto /app/ && chmod 775 /app/ && chmod 775 /app/dist

# hadolint ignore=DL3059,DL3016
RUN npm uninstall -g npm && apt-get purge -y --auto-remove git npm apt-transport-https ca-certificates gnupg curl google-cloud-sdk \
    python3-dev lsb-release \
    && rm -rf /var/lib/apt/lists/*
