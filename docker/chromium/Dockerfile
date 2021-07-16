FROM demisto/python3-deb:3.9.6.22912

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  python3-dev \
  wget \
  libxss1 \
  libappindicator1 \
  poppler-utils \
  fonts-noto-cjk \
  fonts-noto-core \
  zlib1g-dev \
&& pip3 install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  python3-dev \
  zlib1g-dev \
&& rm -rf /var/lib/apt/lists/*

# Based on instructions at: https://tecadmin.net/setup-selenium-with-chromedriver-on-debian/
# To update the chorome and chromedriver versions first check the latest available
# To see available versions of chrome you can run: 
#     docker run --rm -it devdemisto/chromium:1.0.0.22085 bash -c 'apt-get update && apt-cache policy google-chrome-stable'
#
# To see available chromedriver go to https://chromedriver.storage.googleapis.com/ and search for the major version
# of chrome(for  example 91.0).

# Then replace the versions in the env vars
ENV CHROME_VERSION=91.0.4472.114-1
ENV CHROMEDRIVER_VERSION=91.0.4472.101

# Deps needed by google-chrome
RUN apt-get update && apt-get -t buster-backports install -y --no-install-recommends \
  gnupg1 \
  libgtk-3-0 \
  libu2f-udev \
  udev \
&& apt-get update && apt-get install -y --no-install-recommends \
  curl \
  unzip \
&& curl -sS -o - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
&& echo "deb [arch=amd64]  http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list \
&& wget https://chromedriver.storage.googleapis.com/${CHROMEDRIVER_VERSION}/chromedriver_linux64.zip \
&& unzip chromedriver_linux64.zip \
&& mv chromedriver /usr/bin/chromedriver \
&& rm -rf chromedriver_linux64.zip \
&& apt-get purge -y --auto-remove \
  curl \
  unzip \
&& apt-get -y update && apt-get install -y google-chrome-stable=${CHROME_VERSION} \
&& google-chrome --version \
&& chromedriver --version \
&& rm -rf /var/lib/apt/lists/*
