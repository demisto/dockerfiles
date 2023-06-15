# Last modified: 2023-06-15T08:34:02.737569+00:00
FROM demisto/python3-deb:3.10.12.63330


COPY requirements.txt .

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
  python3-dev \
  wget \
  libxss1 \
  poppler-utils \
  fonts-noto-cjk \
  fonts-noto-core \
  zlib1g-dev \
&& wget http://http.us.debian.org/debian/pool/main/liba/libappindicator/libappindicator1_0.4.92-7_amd64.deb -O /tmp/libappindicator1_0.4.92-7_amd64.deb \
&& wget http://http.us.debian.org/debian/pool/main/libi/libindicator/libindicator7_0.5.0-4_amd64.deb -O /tmp/libindicator7_0.5.0-4_amd64.deb \
&& apt-get install -y  /tmp/libindicator7_0.5.0-4_amd64.deb /tmp/libappindicator1_0.4.92-7_amd64.deb \
&& pip3 install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  python3-dev \
  zlib1g-dev \
&& rm -rf /var/lib/apt/lists/*

# Based on instructions at: https://tecadmin.net/setup-selenium-with-chromedriver-on-debian/
# Will install the latest version available from the chrome repo.
# To see available chromedriver go to https://chromedriver.storage.googleapis.com/ and search for the major version
# of chrome(for  example 91.0).

COPY download_chromedriver.sh .

# Deps needed by google-chrome
RUN apt-get update && apt-get -t bullseye-backports install -y --no-install-recommends \
  gnupg1 \
  libgtk-3-0 \
  libu2f-udev \
  udev \
&& apt-get update && apt-get install -y --no-install-recommends \
  curl \
  unzip \
&& curl -sS -o - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
&& echo "deb [arch=amd64]  http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list \
&& apt-get -y update && apt-get install -y google-chrome-stable \
&& apt-get install -y tigervnc-standalone-server x11-utils imagemagick \
&& ./download_chromedriver.sh \
&& unzip chromedriver_linux64.zip \
&& mv chromedriver /usr/bin/chromedriver \
&& rm -rf chromedriver_linux64.zip \
&& google-chrome --version \
&& chromedriver --version \
&& apt-get purge -y --auto-remove \
  curl \
  unzip \
&& rm -rf /var/lib/apt/lists/*

ENV CHROME_EXE="/opt/google/chrome/google-chrome"
