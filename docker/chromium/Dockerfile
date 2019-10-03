FROM demisto/python3-deb:3.7.4.2245

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  python-dev \
  wget \
  libxss1 \
  libappindicator1 \
  poppler-utils \
&& pip3 install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  python-dev \
&& rm -rf /var/lib/apt/lists/*

# Installing Google Chrome 76.0.3809.100 and ChromeDriver 76.0.3809.126
# IMPORTANT: we use wget to avoid using copy to get a small image. If you update the zip files you must update the download links to the proper commit hash
RUN apt-get update && \
wget -q https://github.com/demisto/dockerfiles/raw/133fbf8dbb1c1baf7f0b991cc85ef1dc6e676624/docker/chromium/chromedriver_linux64.zip && \
wget -q https://github.com/demisto/dockerfiles/raw/133fbf8dbb1c1baf7f0b991cc85ef1dc6e676624/docker/chromium/google-chrome-stable_current_amd64.deb && \
dpkg -i google-chrome*.deb; \
apt --fix-broken -y install; \
apt-get -y install unzip \
&& unzip chromedriver_linux64.zip \
&& mv chromedriver /usr/bin/chromedriver \
&& rm -rf /var/lib/apt/lists/* google-chrome*.deb chromedriver_linux64.zip \
&& google-chrome --version \
&& chromedriver --version
