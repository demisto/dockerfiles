
# Last modified: 2024-10-01T00:50:04.196763+00:00
FROM demisto/python3-deb:3.11.10.112962

COPY requirements.txt .

ARG POPPLER_VERSION=24.02.0

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
  python3-dev \
  wget \
  libxss1 \
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
&& rm -rf /var/lib/apt/lists/* \
&& touch /var/chrome_headless.log \
&& chmod 777 /var/chrome_headless.log \
&& touch /var/chrome_instances.tsv \
&& chmod 777 /var/chrome_instances.tsv \
&& touch /var/rasterizations_counter.txt \
&& chmod 777 /var/rasterizations_counter.txt

# Based on instructions at: https://tecadmin.net/setup-selenium-with-chromedriver-on-debian/
# Will install the latest version available from the chrome repo.
# To see available chromedriver go to https://chromedriver.storage.googleapis.com/ and search for the major version
# of chrome(for  example 91.0).

COPY download_chromedriver.sh .

# Deps needed by google-chrome
RUN apt-get update && apt-get -t bullseye-backports install -y --no-install-recommends \
  jq \
  gnupg2 \
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
&& unzip chromedriver-linux64.zip \
&& mv chromedriver-linux64/chromedriver /usr/bin/chromedriver \
&& rm -rf chromedriver-linux64.zip \
&& rm download_chromedriver.sh \
&& google-chrome --version \
&& chromedriver --version

# Install latest Poppler
RUN apt-get install -y libfreetype-dev libfontconfig-dev libboost-dev libpng-dev zlib1g-dev liblcms2-dev libcurl4 libcurl4-gnutls-dev \
&& apt-get install -y libjpeg-dev libcairo-dev libopenjp2-7-dev libtiff-dev libnss3-dev \
&& apt-get install -y build-essential \
&& apt-get install -y libgpgmepp-dev qtbase5-dev libcairo2-dev \
&& apt-get install -y xz-utils cmake \
&& wget https://poppler.freedesktop.org/poppler-${POPPLER_VERSION}.tar.xz -v \
&& tar -xf ./poppler-${POPPLER_VERSION}.tar.xz \
&& cd poppler-${POPPLER_VERSION} \
&& mkdir -p build \
&& cd build \
&& apt-get install -y git \
&& git clone git://git.freedesktop.org/git/poppler/test \
&& cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr -DTESTDATADIR=$PWD/testfiles -DENABLE_QT6=OFF -DENABLE_UNSTABLE_API_ABI_HEADERS=ON -DENABLE_GPGME=OFF .. \
&& make install \
&& . ~/.bashrc \
&& ldconfig "$(which pdftoppm)" \
&& pdftoppm -v \
&& cd ../.. \
&& rm poppler-${POPPLER_VERSION}.tar.xz \
&& rm -rf poppler-${POPPLER_VERSION}/ \
&& apt remove libaom0 -y

RUN apt-get purge -y --auto-remove \
  curl \
  git \
  unzip \
  jq \
&& rm -rf /var/lib/apt/lists/*

ENV CHROME_EXE="/opt/google/chrome/google-chrome"
