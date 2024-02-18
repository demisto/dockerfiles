
# Last modified: 2024-02-14T00:49:05.078289+00:00
FROM demisto/python3-deb:3.10.13.87666

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
&& rm -rf /var/lib/apt/lists/* \
&& touch /var/chrome_headless.log \
&& chmod 777 /var/chrome_headless.log \
&& touch /var/port.txt \
&& chmod 777 /var/port.txt \
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

RUN pdftoppm -v
RUN ls -lt
# RUN wget https://poppler.freedesktop.org/poppler-24.02.0.tar.xz --no-check-certificate -v
RUN curl -k https://poppler.freedesktop.org/poppler-24.02.0.tar.xz --output poppler-24.02.0.tar.xz
RUN ls -lt
RUN apt-get update
RUN apt-get install xz-utils
RUN tar -xf ./poppler-24.02.0.tar.xz
RUN cd poppler-24.02.0
RUN mkdir -p build
RUN cd build
RUN apt-get install -y git
RUN git clone git://git.freedesktop.org/git/poppler/test
RUN apt-get install -v -y libfreetype-dev libfontconfig-dev libboost-dev libpng-dev zlib1g-dev liblcms2-dev libcurl4 libcurl4-gnutls-dev
RUN apt-get install -v -y libjpeg-dev libcairo-dev libopenjp2-7-dev libtiff-dev libcurl4-gnutls-dev libnss3-dev
RUN apt-get install -v -y build-essential
RUN apt-get install -v -y libnss3-dev libgpgmepp-dev qtbase5-dev libcairo2-dev libboost-dev
RUN cmake -DCMAKE_INSTALL_MANDIR:PATH=/usr/local/share/man -DENABLE_GPGME=OFF ..
RUN cd /poppler-24.02.0
RUN make install
RUN . ~/.bashrc
RUN sudo ldconfig "$(which pdftoppm)"
RUN pdftoppm -v

RUN apt-get purge -y --auto-remove \
  curl \
  unzip \
  jq \
&& rm -rf /var/lib/apt/lists/*

ENV CHROME_EXE="/opt/google/chrome/google-chrome"
